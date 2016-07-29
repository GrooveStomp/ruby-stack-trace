#define _GNU_SOURCE

#include <limits.h>
#include <stdlib.h> /* EXIT_SUCCESS, EXIT_FAILURE */
#include <stdio.h>
#include <alloca.h>
#include <sys/uio.h> /* process_vm_readv */
#include <sys/wait.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h> /* For open() */
#include <sys/stat.h>  /* For open() */
#include <fcntl.h>     /* For open() */

#include "dwarf.h"
#include "libdwarf.h"

const unsigned int STRING_ALLOC_SIZE = 512;

void
abort_with_message(char *format_string, ...)
{
        va_list args;
        va_start(args, format_string);
        fprintf(stderr, format_string, args);
        exit(EXIT_FAILURE);
}

char *
line_with_string(char *haystack, char *needle)
{
        char *mem_ptr = strstr(haystack, needle);
        if(mem_ptr == NULL) return(NULL);

        for(; mem_ptr > haystack && *mem_ptr != '\n'; --mem_ptr);

        if((*mem_ptr != '\n') && (mem_ptr != haystack)) return(NULL);

        return(++mem_ptr);
}

uintptr_t
read_hexadecimal_address(char *string, char terminal)
{
        /* Now Read the first address part - before the first '-'. */
        char *end_of_integer = strchr(string, terminal);
        if(end_of_integer == NULL) abort_with_message("Couldn't parse output");

        unsigned int string_size = end_of_integer - string;
        char *str_cpy = (char *)alloca(string_size + 1);
        memcpy(str_cpy, string, string_size);
        str_cpy[string_size] = '\0';

        uintptr_t integer = (uintptr_t)strtoull(str_cpy, NULL, 16);
        return(integer);
}

/*
  You can't use fseek on a file in the proc file tree, so brute force it by
  counting all bytes until EOF.
*/
size_t
proc_file_size(char *filename)
{
        FILE *proc_file = fopen(filename, "r");
        if(!proc_file) abort_with_message("Failed to open file: %s\n", filename);

        /* Get size of file */
        size_t file_size = 0;
        for(; fgetc(proc_file) != EOF; file_size++);

        /* Now reopen the file since we've read to the end */
        fclose(proc_file);

        return(file_size);
}

void
copy_file_into_memory(char *file_name, size_t file_size, char *file_buffer)
{
        FILE *file = fopen(file_name, "r");
        if(!file) abort_with_message("Failed to open file: %s\n", file_name);

        int bytes_read = fread(file_buffer, 1, file_size, file);
        if(bytes_read != file_size) abort_with_message("Expected %i bytes to be read; instead read %i bytes\n", file_size, bytes_read);

        fclose(file);
}

/*
  This looks in /proc/{id}/maps to find the base address for the process.
*/
uintptr_t
ruby_base_address(char *pid)
{
        char *file_name = (char *)alloca(STRING_ALLOC_SIZE);
        snprintf(file_name, STRING_ALLOC_SIZE, "/proc/%s/maps", pid);

        size_t file_size = proc_file_size(file_name);
        char *file_buffer = (char *)alloca(file_size);
        copy_file_into_memory(file_name, file_size, file_buffer);

        /*
          Look in the file for a line like:
          55efb2c45000-55efb2f12000 r-xp 00000000 00:2c 4238303 /home/aaron/.rubies/ruby-2.2.4/bin/ruby
        */
        char *mem_ptr = line_with_string(file_buffer, "bin/ruby");
        uintptr_t address = read_hexadecimal_address(mem_ptr, '-');

        return(address);
}

/*
  This function assumes the child process has already been forked, then the
  function is invoked with the Ruby Pid and the shared pipe between this child
  process and the parent process.
  Simply execute `nm' and write the output back to the parent process.
*/
void
execute_nm_child_process(int pipe_read, int pipe_write, char *pid)
{
        while(1)
        {
                int dup_result = dup2(pipe_write, STDOUT_FILENO);
                if(dup_result != -1 || errno != EINTR)
                        break;
        }
        close(pipe_write);
        close(pipe_read);

        char *proc_exe_path = "/proc/%s/exe";
        int alloc_size = strlen(proc_exe_path) + strnlen(pid, 64);
        char *filename = (char *)alloca(alloc_size);
        snprintf(filename, alloc_size, proc_exe_path, pid);

        /* execl replaces the current process with the named process. */
        execl("/usr/bin/nm", "nm", filename, (char *)NULL);

        /*
          if execl fails, then the current process continues and we'll hit the
          abort message.
        */
        abort_with_message("Failed to execute process `nm'\n");
}

/*
  To get the address offset specified by the Ruby VM, we'll use `nm' and the
  `proc' file system. To do this, we'll fork a child process whilch will
  execute said command, and we'll pipe the output back into the parent process
  so we can read it.
  We're looking for a line that matches `ruby_current_thread' and we'll just
  grab the hexadecimal number that starts the line.
*/
uintptr_t
ruby_relative_address(char *external_pid)
{
        uintptr_t address;

        int comm_pipe[2];
        if(pipe(comm_pipe) < 0) abort_with_message("Error creating pipe\n");

        int pipe_read = comm_pipe[0];
        int pipe_write = comm_pipe[1];

        int pid = fork();
        if(pid == 0) /* A pid of 0 indicates the child process. */
        {
                execute_nm_child_process(pipe_read, pipe_write, external_pid);
        }
        close(pipe_write);

        char buffer[4096];
        int reading_pipe = 1;
        while(reading_pipe)
        {
                size_t bytes_read = read(pipe_read, buffer, sizeof(buffer));
                switch(bytes_read)
                {
                        case(-1):
                        {
                                if(errno == EINTR) continue;
                                abort_with_message("Encountered an error reading child process output\n");
                        }
                        break;

                        case(0):
                        {
                                reading_pipe = 0;
                        }
                        break;

                        default:
                        {
                                char *mem_ptr = line_with_string(buffer, "ruby_current_thread");
                                if(mem_ptr != NULL)
                                {
                                        address = read_hexadecimal_address(mem_ptr, ' ');
                                }
                        }
                        break;
                }
        }

        close(pipe_read);
        wait(0);

        return(address);
}

void *
read_remote_address(pid_t pid, void *address)
{
        /* Copy Remote Process Address into local process memory */
        struct iovec local_iov;
        struct iovec remote_iov;
        void *remote_data;

        local_iov.iov_base = remote_data;
        local_iov.iov_len = sizeof(void *);

        remote_iov.iov_base = address;
        remote_iov.iov_len = sizeof(void *);

        size_t readv_result = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
        if(readv_result <= 0) abort_with_message("Failed to read data\n");

        return(remote_data);
}

void
usage()
{
        printf("usage: ruby-stack-trace ruby_pid\n");
        printf("  Specify '-h' or '--help' for this help text.\n");
        exit(EXIT_SUCCESS);
}

struct srcfilesdata
{
    char **srcfiles;
    Dwarf_Signed srcfilescount;
    int srcfilesres;
};
static int unittype      = DW_UT_compile;
static Dwarf_Bool g_is_info = 1;
static void get_die_and_siblings(Dwarf_Debug, Dwarf_Die, int, int, struct srcfilesdata *);

/* TODO(AARON): libdwarf:
   https://sourceforge.net/p/libdwarf/code/ci/master/tree/
*/
int
main(int num_args, char **args)
{
        for(int i = 0; i < num_args; ++i)
        {
                if(strncmp(args[i], "-h", 2) == 0 ||
                   strncmp(args[i], "--help", 6) == 0)
                {
                        usage();
                }
        }
        if(num_args != 2) usage();
        char *pid_string = args[1];

        /*
          1. Get the base memory address for the running ruby process (/proc/pid/maps | grep bin/ruby)
          2. Get the relative offset used by the process itself. (nm /proc/pid/exe | grep current_ruby_thread)
          3. Add these together to get the effective address.
          4. process_vm_readv to read data at the effective address to get the memory pointer.
          5. process_vm_readv to read the rb_thread_struct memory (DW_AT_byte_size) from memory pointer.
          6. Read the cfp member from the rb_thread_struct.
             (rb_thread_struct memory + DW_AT_data_member_location where
              DW_AT_name == "cfp")
          7. Repeat above for DW_TAG_typedef:DW_AT_name(rb_control_frame_t)
             ie.: DW_TAG_structure_type:DW_AT_name(rb_control_frame_struct)
             Julia does this bit:

                 unsafe {
                         let result = copy_address_raw(thread.cfp as *mut c_void, 100 * mem::size_of::<ruby_vm::rb_control_frame_t>(), pid);
                         slice::from_raw_parts(result.as_ptr() as *const ruby_vm::rb_control_frame_t, 100)
                 }
        */

        uintptr_t base_address = ruby_base_address(pid_string);
        printf("%-30s hex: %012lX dec: %015lu\n", "Base address", base_address, base_address);

        uintptr_t relative_address = ruby_relative_address(pid_string);
        printf("%-30s hex: %012lX dec: %015lu\n", "Relative address", relative_address, relative_address);

        uintptr_t ruby_proc_address = base_address + relative_address;
        printf("%-30s hex: %012lX dec: %015lu\n", "Process address", ruby_proc_address, ruby_proc_address);

        pid_t pid = (pid_t)strtol(pid_string, NULL, 10);
        printf("%-30s %i\n", "Pid", pid);

        void *ruby_current_thread_address = read_remote_address(pid, (void *)ruby_proc_address);
        printf("%-30s hex: %012lX dec: %015lu\n", "Current thread address", (uintptr_t)ruby_current_thread_address, (uintptr_t)ruby_current_thread_address);

        void *thread = read_remote_address(pid, ruby_current_thread_address);
        printf("%-30s hex: %012lX dec: %015lu\n", "Thread address", (uintptr_t)thread, (uintptr_t)thread);

        /**********************************************************************
         * DWARF stuff
         **********************************************************************/

        char *proc_exe_path = "/proc/%s/exe";
        int alloc_size = strlen(proc_exe_path) + strnlen(pid_string, 64);
        char *filename = (char *)alloca(alloc_size);
        snprintf(filename, alloc_size, proc_exe_path, pid_string);

        int file_descriptor = open(filename, O_RDONLY);

        Dwarf_Debug dwarf_debug;
        Dwarf_Error *dwarf_error;
        int res = dwarf_init(file_descriptor, DW_DLC_READ, NULL, (Dwarf_Ptr)1,
                             &dwarf_debug, dwarf_error);
        if(res != DW_DLV_OK) abort_with_message("Failed to initialize libdwarf\n");

        {
                Dwarf_Unsigned cu_header_length = 0;
                Dwarf_Half     version_stamp = 0;
                Dwarf_Unsigned abbrev_offset = 0;
                Dwarf_Half     address_size = 0;
                Dwarf_Half     offset_size = 0;
                Dwarf_Half     extension_size = 0;
                Dwarf_Sig8     signature;
                Dwarf_Unsigned typeoffset = 0;
                Dwarf_Unsigned next_cu_header = 0;
                Dwarf_Half     header_cu_type = unittype;
                Dwarf_Bool     is_info = g_is_info;
                Dwarf_Error error;
                int cu_number = 0;

                /*
                  - Find DW_TAG_structure_type "rb_thread_struct"
                    - All members are subsequent "DW_TAG_member"s.
                    - Get the DW_AT_name, DW_AT_type

                  In Julia's code she predefines all the Ruby VM types and then
                  reads the corresponding chunk of memory to fill that.
                  Instead of doing that, we want to read the corresponding
                  memory and then dynamically access it according to the debug
                  info given by DWARF.

                  DW_TAG_structure_type
                    DW_AT_name rb_thread_struct
                    DW_AT_byte_size 0x000003f0

                  I believe this means read 0x3f0 bytes from memory.
                  Search through DW_TAG_member sub-items and find the one with
                  DW_AT_name == "cfp" and get DW_AT_data_member_location.
                  Now our pointer is at Memory + DW_AT_data_member_location.

                  TODO: DW_AT_type -> Need to find out size of data to read and type.
                  TODO: Need to find out where rb_thread_struct is in memory dump.
                 */

                while(1)
                {
                        Dwarf_Die no_die = 0;
                        Dwarf_Die cu_die = 0;
                        int res = DW_DLV_ERROR;
                        struct srcfilesdata sf;
                        sf.srcfilesres = DW_DLV_ERROR;
                        sf.srcfiles = 0;
                        sf.srcfilescount = 0;
                        memset(&signature,0, sizeof(signature));

                        res = dwarf_next_cu_header_d(
                                dwarf_debug, is_info, &cu_header_length, &version_stamp,
                                &abbrev_offset, &address_size, &offset_size,
                                &extension_size, &signature, &typeoffset,
                                &next_cu_header, &header_cu_type, &error
                        );
                        if(DW_DLV_NO_ENTRY == res) break;
                        if(DW_DLV_ERROR == res) abort_with_message(dwarf_errmsg(error));

                        /* The CU will have a single sibling, a cu_die. */
                        res = dwarf_siblingof_b(dwarf_debug, no_die,is_info, &cu_die, &error);
                        if(DW_DLV_ERROR == res) abort_with_message(dwarf_errmsg(error));
                        if(DW_DLV_NO_ENTRY == res) abort_with_message("This should never occur!\n");

                        get_die_and_siblings(dwarf_debug,cu_die,is_info,0,&sf);
                        dwarf_dealloc(dwarf_debug,cu_die,DW_DLA_DIE);

                        for(Dwarf_Signed sri = 0; sri < sf.srcfilescount; ++sri)
                        {
                                dwarf_dealloc(dwarf_debug, sf.srcfiles[sri], DW_DLA_STRING);
                        }
                        dwarf_dealloc(dwarf_debug, sf.srcfiles, DW_DLA_LIST);
                        sf.srcfilesres = DW_DLV_ERROR;
                        sf.srcfiles = 0;
                        sf.srcfilescount = 0;

                        ++cu_number;
                }
        }

        res = dwarf_finish(dwarf_debug, dwarf_error);
        if(res != DW_DLV_OK) abort_with_message("Failed to shutdown libdwarf\n");

        close(file_descriptor);

        return(EXIT_SUCCESS);
}


static void
get_die_and_siblings(Dwarf_Debug dwarf_debug, Dwarf_Die in_die, int is_info,int in_level, struct srcfilesdata *sf)
{
//        print_die_data(dwarf_debug,in_die,in_level,sf);

        while(1)
        {
                int res = DW_DLV_ERROR;
                Dwarf_Die cur_die=in_die;
                Dwarf_Die child = 0;
                Dwarf_Error error = 0;
                Dwarf_Die sib_die = 0;

                res = dwarf_child(cur_die, &child, &error);
                if(DW_DLV_ERROR == res)
                        abort_with_message("Error in dwarf_child, level %d\n", in_level);

                if(DW_DLV_OK == res)
                        get_die_and_siblings(dwarf_debug, child, is_info, in_level + 1, sf);

                /* res == DW_DLV_NO_ENTRY */
                res = dwarf_siblingof_b(dwarf_debug,cur_die,is_info,&sib_die, &error);
                if(res == DW_DLV_NO_ENTRY)
                        break;

                if(res == DW_DLV_ERROR)
                        abort_with_message(dwarf_errmsg(error));

                /* res == DW_DLV_OK */
                if(cur_die != in_die)
                        dwarf_dealloc(dwarf_debug,cur_die,DW_DLA_DIE);

                cur_die = sib_die;
//                print_die_data(dwarf_debug,cur_die,in_level,sf);
        }

        return;
}
