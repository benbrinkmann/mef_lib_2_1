/*
		read_mef_header.c
 
 Program to read mef format file header (v.2) and display output 
 
 Multiscale electrophysiology format example program
 

 To compile for a 64-bit intel system: (options will vary depending on your particular compiler and platform)
 Intel Compiler: icc read_mef_header.c mef_lib.c endian_functions.c AES_Encryption.c -o rmh -fast -m64
 GCC: gcc read_mef_header.c mef_lib.c endian_functions.c AES_Encryption.c -o rmh -O3 -arch x86_64
 
 This software is made freely available under the GNU public license: http://www.gnu.org/licenses/gpl-3.0.txt
 
 Thanks to all who acknowledge the Mayo Systems Electrophysiology Laboratory, Rochester, MN
 in academic publications of their work facilitated by this software.
 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "mef.h"


int main (int argc, const char * argv[]) {
	si4 i, num;
	char password[32];

	ui1 *bk_hdr;
	FILE *fp;
	MEF_HEADER_INFO *header;
	
	if (argc < 2 || argc > 3) 
	{
		(void) printf("USAGE: %s file_name [password] \n", argv[0]);
		return(1);
	}

	*password = 0;
	
	if (argc > 2)
	{
		//check password length
		if (strlen(argv[2]) > 16) {
			fprintf(stderr, "Error: Password cannot exceed 16 characters\n");
			return 1;
		}
		strcpy(password, argv[2]);
	}

	header = malloc(sizeof(MEF_HEADER_INFO)); memset(header, 0, sizeof(MEF_HEADER_INFO));
	
	fp = fopen(argv[1], "r");
	if (fp == NULL) {
			fprintf(stderr, "Error opening file %s\n", argv[1]);
			return 1;
		}		
	
	bk_hdr = calloc(sizeof(ui1), MEF_HEADER_LENGTH);	
	num = fread(bk_hdr, 1, MEF_HEADER_LENGTH, fp);
	if (num != MEF_HEADER_LENGTH) {
		fprintf(stderr, "Error reading file %s\n", argv[1]);
		return 1;
	}
	
	(void)read_mef_header_block(bk_hdr, header, password);
	showHeader(header);
	
	printf("Done Showing hdr\n");
	
	free(bk_hdr); bk_hdr = NULL;
	return 0;
}
