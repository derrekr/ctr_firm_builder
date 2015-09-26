#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "polarssl/sha2.h"

#define FIRM_MAX_SIZE	0x400000
typedef unsigned char u8;

static char *firm_magic = "FIRM";
static char *haxx_magic = "HAXX";

// structs from ctrtool
typedef struct
{
	u8 offset[4];
	u8 address[4];
	u8 size[4];
	u8 type[4];
	u8 hash[32];
} firm_sectionheader;

typedef struct
{
	u8 magic[4];
	u8 reserved1[4];
	u8 entrypointarm11[4];
	u8 entrypointarm9[4];
	u8 reserved2[0x30];
	firm_sectionheader section[4];
	u8 signature[0x100];
} firm_header;

unsigned char *firm_buf;

unsigned int addSection(FILE *sectionf, unsigned int index, unsigned int addr,
	unsigned int offset, unsigned int size, unsigned int type)
{
	unsigned int padding;
	unsigned int size_aligned;
	unsigned char *section_buf;
	firm_header *hdr;
	firm_sectionheader *section_hdr;

	if (size == 0)
		return 0;

	// align section to 0x200-bytes
	padding = (0x200 - (size % 0x200)) % 0x200;
	size_aligned = size + padding;

	section_buf = (unsigned char *)firm_buf + offset;
	fread(section_buf, 1, size, sectionf);

	// fill padding
	memset(section_buf + size, 0x00, padding);

	// add firm header entry
	hdr = (firm_header *)firm_buf;
	section_hdr = &(hdr->section[index]);
	memcpy(section_hdr->offset, &offset, 4);
	memcpy(section_hdr->address, &addr, 4);
	memcpy(section_hdr->size, &size_aligned, 4);
	memcpy(section_hdr->type, &type, 4);
	sha2(section_buf, size_aligned, section_hdr->hash, 0);

	return size_aligned;
}

int main(int argc, char* argv[])
{
	unsigned int section_count;
	struct stat file_stat;
	FILE *fout;

	if (argc < 7)
	{
		printf("firm_builder by derrek\n");
		printf("Usage: %s <output file> <arm9 entry addr> <arm11 entry addr> <section0 loading addr> <section0 copy method> <section0 binary> <section1 loading addr> ...\n", argv[0]);
		printf("The maximum section count is 4.\n");
		return 1;
	}

	section_count = (argc - 4) / 3;	// three params per section
	if (section_count > 4)
	{
		printf("Error: the maximum section count is 4.\n");
		return 3;
	}

	firm_buf = (unsigned char *)malloc(FIRM_MAX_SIZE);
	memset(firm_buf, 0x00, 0x100);
	
	FILE *section_file;
	unsigned int section_size;
	unsigned int section_addr;
	unsigned char section_type;
	unsigned int cur_offset = 0x200;	// current offset in firm_buf

	// loop through all sections
	for (unsigned int i = 0; i < section_count*3; i+=3)
	{
		if (stat(argv[i+6], &file_stat) == -1)
		{
			printf("Failed to stat %s\n", argv[i+6]);
			return 4;
		}

		section_size = file_stat.st_size;
		unsigned int padding = (0x200 - (section_size % 0x200)) % 0x200;
		if ((section_size + padding > FIRM_MAX_SIZE - 0x200) || (section_size + padding + cur_offset > FIRM_MAX_SIZE - 0x200))
		{
			printf("Not enough space to fit section %s into the FIRM image %s\n", argv[i+6], argv[i+1]);
			return 5;
		}

		section_file = fopen(argv[i+6], "rb");
		if (section_file == NULL)
		{
			printf("Failed to fopen section file %s.\n", argv[i+6]);
			return 6;
		}

		sscanf(argv[i+5], "%x", &section_type);
		if (section_type > 2)
		{
			printf("Warning: section type %i might be unsupported.\n", section_type);
		}
		sscanf(argv[i+4], "%x", &section_addr);

		cur_offset += addSection(section_file, i/3, section_addr, cur_offset, section_size, section_type);

		fclose(section_file);
	}

	// setup firm header
	firm_header *hdr = (firm_header *)firm_buf;
	memcpy(hdr->magic, firm_magic, 4);
	//memcpy(firm_buf + 0x10, haxx_magic, 4);
	unsigned int firm_entry;
	sscanf(argv[3], "%x", &firm_entry);
	memcpy(hdr->entrypointarm11, &firm_entry, 4);
	sscanf(argv[2], "%x", &firm_entry);
	memcpy(hdr->entrypointarm9, &firm_entry, 4);
	// this should be replaced manually
	memset(hdr->signature, 0xAA, 0x100);

	fout = fopen(argv[1], "wb");
	if (fout == NULL)
	{
		printf("Failed to fopen output file for writing.\n");
		return 2;
	}
	fwrite(firm_buf, cur_offset, 1, fout);
	fclose(fout);

	return 0;
}
