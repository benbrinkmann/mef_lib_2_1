/*

 *
 // copyright 2012, Mayo Foundation, Rochester MN. All rights reserved
 // usage and modification of the MEF source code is governed by the Apache 2.0 license
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <time.h>

#include "mef.h"


int main (int argc, const char * argv[]) {
	int i, numFiles, result;
	ui8 error_count;
	char subject_password[32], logname[200];
	char *strPointer;

	
	if (argc < 2) 
	{
		(void) printf("USAGE: %s file_name(s) -l logfile \n", argv[0]);
		return(1);
	}
	
	numFiles = argc - 1;
	
	//read command line options
	*logname=0;
	for (i = 1; i < argc; i++)
	{
		if (*argv[i] == '-') {
			switch (argv[i][1]) {
				case 'p': //password
					strcpy(subject_password, argv[i+1]);
					numFiles -= 2;
					break;
				case 'l': //log file
					strcpy(logname, argv[i+1]);
					numFiles -= 2;
					break;
				default:
					fprintf(stderr, "Error: unrecognized option %s\n", argv[i]);
					return(1);
			}
		}
	}
	
	error_count = 0;
	
	for (i = 1; i <= numFiles; i++)
	{
		result = validate_mef(argv[i], logname, subject_password);
		fprintf(stdout, "%d errors found in file %s\n\n", result, argv[i] );
		if (result !=0) error_count++;
	}
	
	fprintf(stdout, "\nMEF file checking of %d files completed with errors detected in %"PRIu64" files.\n", numFiles, error_count );
	
	return 0;
}

