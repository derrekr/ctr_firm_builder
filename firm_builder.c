/*
 *  firm_builder is a tool for generating Nintendo 3DS FIRM containers.
 *  Copyright (C) 2015-2017 derrek
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/
 */
 
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "polarssl/sha2.h"

#define FIRM_MAX_SIZE	0x400000
typedef unsigned char u8;

static const char *firm_magic = "FIRM";

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

static unsigned int addSection(FILE *sectionf, unsigned int index, unsigned int addr,
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
	if (fread(section_buf, 1, size, sectionf) != size)
		return 0;

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
	FILE *section_file;
	unsigned int section_size;
	unsigned int section_addr;
	unsigned char section_type;
	unsigned int cur_offset;	// current offset in firm_buf
	unsigned int firm_entry;

	if (argc < 7)
	{
		printf("firm_builder for 3DS (C) 2015-2017 derrek\n");
		printf("Usage: %s <output file> <arm9 entry addr> <arm11 entry addr> ", argv[0]);
		printf("<section0 loading addr> <section0 copy method> <section0 binary> ");
		printf("<section1 loading addr> ...\n");
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
	if (firm_buf == NULL)
	{
		printf("Error: Out of memory.\n");
		return 7;
	}
	
	memset(firm_buf, 0x00, 0x100);

	
	/* setup firm header */
	
	firm_header *hdr = (firm_header *)firm_buf;
	memcpy(hdr->magic, firm_magic, 4);
	
	if (sscanf(argv[3], "%x", &firm_entry) != 1)
	{
		printf("Invalid ARM11 entrypoint addr %s.\n", argv[3]);
		return 10;
	}
	memcpy(hdr->entrypointarm11, &firm_entry, 4);
	
	if (sscanf(argv[2], "%x", &firm_entry) != 1)
	{
		printf("Invalid ARM11 entrypoint addr %s.\n", argv[3]);
		return 11;
	}
	memcpy(hdr->entrypointarm9, &firm_entry, 4);
	
	// this should be replaced manually
	memset(hdr->signature, 0xAA, 0x100);
	
	
	/* populate firm body */
	
	cur_offset = 0x200;

	// loop through all sections
	for (unsigned int i = 0; i < section_count * 3; i+=3)
	{
		const char *section_addr_string = argv[i+4];
		const char *section_type_string = argv[i+5];
		const char *section_filepath = argv[i+6];
		
		if (stat(section_filepath, &file_stat) == -1)
		{
			printf("Failed to stat %s.\n", section_filepath);
			return 4;
		}

		section_size = file_stat.st_size;
		unsigned int padding = (0x200 - (section_size % 0x200)) % 0x200;
		const unsigned int real_max_size = FIRM_MAX_SIZE - sizeof(firm_header);
		
		if ((section_size > real_max_size) ||
			(section_size + padding > real_max_size) ||
			(section_size + padding + cur_offset > real_max_size))
		{
			printf("Not enough space to fit section %s into the FIRM image.\n",
					section_filepath);
			return 5;
		}

		section_file = fopen(section_filepath, "rb");
		if (section_file == NULL)
		{
			printf("Failed to fopen section file %s.\n", section_filepath);
			return 6;
		}

		if (sscanf(section_type_string, "%x", &section_type) != 1)
		{
			printf("Invalid section type %s.\n", section_type_string);
			return 8;
		}
		
		if (section_type > 2)
		{
			printf("Warning: section type %i might be unsupported.\n", section_type);
		}
		
		if (sscanf(section_addr_string, "%x", &section_addr) != 1)
		{
			printf("Invalid section address %s.\n", section_addr_string);
			return 9;
		}

		unsigned int bytes_added = addSection(section_file, i/3, section_addr, cur_offset,
									section_size, section_type);

		fclose(section_file);
		
		if (bytes_added == 0)
		{
			printf("Invalid section file.\n");
			return 12;
		}
		
		cur_offset += bytes_added;
	}

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
