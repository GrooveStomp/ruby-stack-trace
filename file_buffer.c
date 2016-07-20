#ifndef _FILE_BUFFER_C
#define _FILE_BUFFER_C

#include <stdio.h>
#include <stdbool.h>

struct buffer {
        char *Data;
	size_t Capacity;
	size_t Length;
};

struct buffer *
buffer_set(struct buffer *Buffer, char *Data, size_t Length, size_t Capacity)
{
	Buffer->Data = Data;
	Buffer->Capacity = Capacity;
	Buffer->Length = Length;
	return(Buffer);
}

bool
copy_file_into_buffer(char *FileName, struct buffer *Mem)
{
	FILE *File = fopen(FileName, "r");
	if(File)
	{
		fseek(File, 0, SEEK_END);
		size_t FileSize = ftell(File);
		if(FileSize + 1 > Mem->Capacity)
		{
			return(false);
		}

		fseek(File, 0, SEEK_SET);
		fread(Mem->Data, 1, FileSize, File);
		Mem->Data[FileSize] = 0;
		Mem->Length = FileSize;

		fclose(File);
	}

	return(true);
}

size_t /* Returns size of file in bytes plus one for trailing '\0'. */
file_size(char *FileName)
{
	FILE *File = fopen(FileName, "r");
	if(File)
	{
		fseek(File, 0, SEEK_END);
		size_t FileSize = ftell(File);
		fclose(File);
		return(FileSize + 1); /* +1 for trailing null byte. */
	}

	return(0);
}

#endif /* _FILE_BUFFER_C */
