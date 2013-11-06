/*

 *  mef2raw32.c
 * 
 
 Program to read mef format file (v.2) and save data as raw 32bit integers 
 Reads entire input file, decodes, and then saves entire output file. 
 
 Multiscale electrophysiology format example program

 
 To compile for a 64-bit intel system: (options will vary depending on your particular compiler and platform)
 Intel Compiler: icc mef2raw32.c mef_lib.c endian_functions.c AES_encryption.c RED_decode.c crc_32.c -o mef2raw -fast -m64
 GCC: gcc mef2raw32.c mef_lib.c endian_functions.c AES_encryption.c RED_encode.c RED_decode.c crc_32.c -o mef2raw -O3 -arch x86_64
  
 
 This software is made freely available under the Apache 2.0 public license: http://www.apache.org/licenses/LICENSE-2.0.html
 
 Thanks to all who acknowledge the Mayo Systems Electrophysiology Laboratory, Rochester, MN
 in academic publications of their work facilitated by this software.
 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "mef.h"


int main (int argc, const char * argv[]) {
	si4 i, num, numBlocks, l, blocks_per_cycle, start_block, end_block;
	si4 *data, *dp;
	ui8 numEntries, inDataLength, outDataLength, bytesDecoded, entryCounter;
	si1 password[16], outFileName[200], path[200], *diff_buffer, *dbp;
	ui1 *hdr_block, *in_data, *idp,  encryptionKey[240];
	FILE *fp, *out_fp;
	MEF_HEADER_INFO header;
	RED_BLOCK_HDR_INFO RED_bk_hdr;
	INDEX_DATA *indx_array;

	blocks_per_cycle = 5000;
	memset(password, 0, 16);
	
	numEntries=0;
	
	if (argc < 2 || argc > 4) 
	{
		(void) printf("USAGE: %s file_name [password] \n", argv[0]);
		return(1);
	}
		
	if (argc > 2) { //check input arguments for password
		strncpy(password, argv[2], 16);
	}
	
	//allocate memory for (encrypted) header block
	hdr_block = calloc(MEF_HEADER_LENGTH, sizeof(ui1));
	
	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		fprintf(stderr, "Error opening file %s\n", argv[1]);
		return 1;
	}
	
	num = fread(hdr_block, 1, MEF_HEADER_LENGTH, fp);
	if (num != MEF_HEADER_LENGTH) {
		fprintf(stderr, "Error reading file %s\n", argv[1]);
		return 1;
	}
		
	read_mef_header_block(hdr_block, &header, password);

	if (header.session_encryption_used && validate_password(hdr_block, password)==0) {
		fprintf(stderr, "Can not decrypt MEF header\n");
		free(hdr_block);
		return 1;
	}

	numBlocks = header.number_of_index_entries;
	numEntries = header.number_of_samples;

	//	inDataLength = header.index_data_offset - header.header_length;
	inDataLength = blocks_per_cycle * header.maximum_compressed_block_size;
	if (header.data_encryption_used) {
		AES_KeyExpansion(4, 10, encryptionKey, header.session_password); 
	}
	else
		*encryptionKey = 0;

	free(hdr_block);
	
	indx_array = calloc(header.number_of_index_entries, sizeof(INDEX_DATA));
	fseek(fp, header.index_data_offset, SEEK_SET);
	num = fread((void*)indx_array, sizeof(INDEX_DATA), header.number_of_index_entries, fp);
	if (num != header.number_of_index_entries) {
		fprintf(stderr, "Can not read block index array\n");
		free(indx_array);
		return 1;
	}
	
	diff_buffer = (si1 *)malloc(header.maximum_block_length * 4);
	in_data = malloc(inDataLength);
	outDataLength = blocks_per_cycle * header.maximum_block_length; //Note: this is only the max data length per decompression cycle....
	//data = calloc(numEntries, sizeof(ui4));	
	data = calloc(outDataLength, sizeof(ui4));
	if (data == NULL || in_data == NULL || diff_buffer == NULL) {
		fprintf(stderr, "malloc error\n");
		return 1;
	}

	//Assemble output filename
	l = (int)strlen(argv[1]);
	memcpy(path, argv[1], l-4);
	path[l-4] = '\0';
	sprintf(outFileName, "%s.raw32", path);
	
	//open output file for writing
	out_fp = fopen(outFileName, "w");
	if (out_fp == NULL) {
		fprintf(stderr, "Error opening file %s\n", outFileName);
		return 1;
	}
	
	fprintf(stdout, "\n\nReading file %s \n", argv[1]);
	start_block = 0;

	fprintf(stdout, "\nDecompressing and writing file %s: %ld entries \n", outFileName, header.number_of_samples);
	
	while( start_block < numBlocks ) {
		end_block = start_block + blocks_per_cycle;
		if (end_block > numBlocks) {
			end_block = numBlocks;
			inDataLength = header.index_data_offset - indx_array[start_block].file_offset;
		}
		else {
			inDataLength = indx_array[end_block].file_offset - indx_array[start_block].file_offset;
		}
		
		fseek(fp, indx_array[start_block].file_offset, SEEK_SET);
		num = fread(in_data, 1, inDataLength, fp);
		if (num != inDataLength) {
			fprintf(stderr, "Data read error \n");
			return 1;
		}
		
		dp = data;	idp = in_data;	dbp = diff_buffer;
		entryCounter = 0;
		for (i=start_block; i<end_block; i++)
		{
			bytesDecoded = RED_decompress_block(idp, dp, dbp, encryptionKey, 0, header.data_encryption_used, &RED_bk_hdr);
			idp += bytesDecoded;
			dp += RED_bk_hdr.sample_count;
			dbp = diff_buffer; //don't need to save diff_buffer- write over
			entryCounter += RED_bk_hdr.sample_count;
		}
		start_block = end_block;	

		num = fwrite(data, sizeof(si4), entryCounter, out_fp);
		if (num != entryCounter) {
			fprintf(stderr, "Error writing file %s\n", argv[1]);
			return 1;
		}
	} //end while()
	
	free(in_data); in_data = NULL;
	free(diff_buffer); diff_buffer = NULL;
	fprintf(stdout, "Decompression complete\n");
	fclose(fp);
	fclose(out_fp);

	free(data); data = NULL;
	return 0;
}
