/*
 *  anon_mef.c
 *  convert_mef
 
 program to anonymize mef2 headers:
 
 *
 * copyright 2012, Mayo Foundation, Rochester MN. All rights reserved
 * usage and modification of the MEF source code is governed by the Apache 2.0 license
  
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "mef.h"

typedef struct {
    sf8 year;
    sf8 month;
    sf8 day; 
    sf8 hour;
    sf8 minute;
    sf8 seconds;
    char* time_zone;
} DATETIME;

int main (int argc, const char * argv[]) {
	si4 i, j, k, numFiles, num, blocksize, pwd_validation;
	ui4 checksum;
	char subject_password[ENCRYPTION_BLOCK_BYTES], session_password[ENCRYPTION_BLOCK_BYTES], data_password[ENCRYPTION_BLOCK_BYTES], temp_str[32];
	const char *txt_info = NULL;
	int numerical=0; 
	ui1 use_numerical=0, key[240], *data_block, mask_timestamps=0;
	ui1 *hdr_block;
    si1 datestr[50];
    si8 offset=0; 
    ui8 new_uUTC=0;
	FILE *fp;
	MEF_HEADER_INFO header;
	INDEX_DATA *file_index;
    RED_BLOCK_HDR_INFO bk_hdr_strct;
    DATETIME dtime;
	
	memset(subject_password, 0, ENCRYPTION_BLOCK_BYTES);
	memset(session_password, 0, ENCRYPTION_BLOCK_BYTES);
	memset(key, 0, 240);
    memset(datestr, 0, 50);
	
	if (argc < 2) 
	{
		(void) printf("USAGE: %s file_name(s) [options]\n", argv[0]);
		(void) printf("Options:\n \t-p <pwd>   \t\tPassword\n");
		(void) printf("\t-t <text>   \t\tBuild new subject name using text\n");
		(void) printf("\t-n <#>   \t\tBuild new subject name using number\n");
		(void) printf("\t-s   \t\t\tReference all timestamps to zero (includes recording start and stop times)\n");
		(void) printf("\t-u   \t\t\tReference all timestamps to the specified uUTC time (includes recording start and stop times)\n");        
		(void) printf("\tNote: output file wil be unencrypted\n");

		return(1);
	}
	
	numFiles = argc - 1;
	
	for (i = 1; i < argc; i++)
	{
		if (*argv[i] == '-') {
			switch (argv[i][1]) {
					
				case 't':	txt_info = argv[i+1];
					numFiles -= 2;
					break;
				case 'n':	use_numerical=1;
					numerical = atoi(argv[i+1]);
					numFiles -= 2 ;
					break;
				case 'p':
					strcpy(subject_password, argv[i + 1]);
					numFiles -= 2 ;
					break;
				case 's':
					mask_timestamps = 1;
                    numFiles--;
                break;
                case 'u':
					mask_timestamps = 1;
                    new_uUTC = atol(argv[i + 1]);
					numFiles -= 2 ;
					break;
                case 'd':
					mask_timestamps = 1;
					strcpy(datestr, argv[i+1]);
					numFiles -= 2 ;
					break;
                default:
                    printf("[%s] Unrecognized option %s\n\n", __FUNCTION__, argv[i]);
                    return(1);
                    
			}
		}
	}
		
	//strcpy(subject_password, argv[numFiles + 1]);
	
	hdr_block = calloc(sizeof(ui1), MEF_HEADER_LENGTH);
	
	if (txt_info != NULL && (strlen(txt_info) > SUBJECT_THIRD_NAME_LENGTH))
	{
		fprintf(stderr, "Error: Text for new subject name cannot exceed %d characters\n", SUBJECT_THIRD_NAME_LENGTH);
		return(1);
	}
	
	for (i=1; i<=numFiles; i++)
	{
		//numFiles--;
		fp = fopen(argv[i], "r+");
		if (fp != NULL) {
			fprintf(stdout, "\n\nReading file %s \n", argv[i]);
			num = fread(hdr_block, 1, MEF_HEADER_LENGTH, fp);
			if (num != MEF_HEADER_LENGTH) {
				fprintf(stderr, "Error reading file %s\n", argv[i]);
				return 1;
			}
			
			(void)read_mef_header_block(hdr_block, &header, subject_password);
            
			if (header.header_version_major == 2) {
				if (header.subject_encryption_used || header.session_encryption_used || header.data_encryption_used)
				{	
					pwd_validation = validate_password(hdr_block, subject_password);
					
					if (header.subject_encryption_used) 
						if (pwd_validation != 1) pwd_validation = 0;
					if (pwd_validation==0)
					{
						fprintf(stderr, "Cannot decrypt file %s: incorrect password: %s\n\n", argv[i], subject_password);
						fclose(fp);
						return 1;
					}
				}
				
                //deal with header recording times
                if (mask_timestamps) {
                    if (new_uUTC==0 && *datestr != 0) {
                        //date specified: Need to translate to uutc and add time offset from the existing file
                    }
                    
                    offset = header.recording_start_time - new_uUTC;
                    header.recording_end_time -= offset;                    
                    header.recording_start_time = new_uUTC;
                }
                
				//set up values to replace subject fields
				if (txt_info == NULL) 
					sprintf(temp_str, "Anonymized");
				else
					sprintf(temp_str, "%s", txt_info);

				if (use_numerical) {
					sprintf(header.subject_id, "9-999-%.3d", numerical);
					sprintf(temp_str, "%s-%d", temp_str, numerical);
				}
				else {
					sprintf(header.subject_id, "9-999-000");
				}
				
				sprintf(header.subject_first_name, "none");
				sprintf(header.subject_second_name, "none");
				sprintf(header.subject_third_name, "%s", temp_str);

				strcpy(session_password, header.session_password);
				
				if (header.data_encryption_used || mask_timestamps) {
					//decrypt and save all RED Block headers in the file
					fprintf(stdout, "Reading data blocks... \n");
					data_block = calloc(header.maximum_compressed_block_size, sizeof(ui1));
					strncpy((char *)data_password, session_password, ENCRYPTION_BLOCK_BYTES); 
					AES_KeyExpansion(4, 10, key, data_password); //pulled out of aes code for efficiency
				
					file_index = (INDEX_DATA *)calloc(header.number_of_index_entries, sizeof(INDEX_DATA));
					if (file_index==NULL) {fclose(fp); fprintf(stderr, "[%d] malloc error\n", __LINE__); return(1);}
					fseek(fp, header.index_data_offset, SEEK_SET);
					num = fread(file_index, header.number_of_index_entries, sizeof(INDEX_DATA), fp);
					
					for (k=0; k<header.number_of_index_entries; k++) {	
						fseek(fp, file_index[k].file_offset, SEEK_SET);
						if (k<header.number_of_index_entries-1) blocksize = file_index[k+1].file_offset - file_index[k].file_offset;
						else blocksize = header.index_data_offset - file_index[k].file_offset;

						num = fread(data_block, blocksize, sizeof(ui1), fp);
						if (header.data_encryption_used)
                            AES_decryptWithKey(data_block + RED_STAT_MODEL_OFFSET, data_block + RED_STAT_MODEL_OFFSET, key);
                        
						num = read_RED_block_header(data_block, &bk_hdr_strct);
                        *(ui8 *)(data_block + RED_UUTC_TIME_OFFSET) = (ui8)((si8)bk_hdr_strct.block_start_time - offset);
                        bk_hdr_strct.block_start_time = (ui8)((si8)bk_hdr_strct.block_start_time - offset);
//                        build_RED_block_header(data_block, &bk_hdr_strct);
                        file_index[k].time -= offset;
                        
						checksum = 0xffffffff;
						for (j = RED_CHECKSUM_OFFSET+RED_CHECKSUM_LENGTH; j < blocksize; j++) //skip first 4 bytes- don't include the CRC itself in calculation
							checksum = update_crc_32(checksum, *(data_block + j));
						*(ui4*)(data_block + RED_CHECKSUM_OFFSET) = checksum; //yes, I realize RED_CHECKSUM_OFFSET is zero, but putting it in may help if that changes in the future
						fseek(fp, file_index[k].file_offset, SEEK_SET);
						num = fwrite(data_block, blocksize, sizeof(ui1), fp);
					}
                    fseek(fp, header.index_data_offset, SEEK_SET);
                    num = fwrite(file_index, header.number_of_index_entries, sizeof(INDEX_DATA), fp);
					free(data_block); data_block = NULL;
					free(file_index); file_index = NULL;
					fprintf(stdout, " done\n");
				}
				
				//prepare to write unencrypted header
				*(header.session_password) = 0; 
				header.subject_encryption_used = 0;
				header.session_encryption_used = 0;
				header.data_encryption_used = 0;
				memset(header.session_password, 0, SESSION_PASSWORD_LENGTH);
				//*subject_password = 0;
				memset(hdr_block, 0, MEF_HEADER_LENGTH);
				(void)build_mef_header_block(hdr_block, &header, session_password);
				fseek(fp, 0, SEEK_SET);
				num = fwrite(hdr_block, 1, MEF_HEADER_LENGTH, fp);
				fclose(fp);
				if (num != MEF_HEADER_LENGTH) {
					fprintf(stderr, "Error writing file %s\n", argv[i]);
					free(hdr_block); hdr_block=NULL;
					return 1;
				}

				fprintf(stdout, "Anonymization successful for %s\n\n", argv[i]);
				showHeader(&header);
			}
			else {
				fprintf(stderr, "File %s does not appear to be a valid MEF 2 file- skipping... \n", argv[i]);
			}
		} 
		else {
			fprintf(stderr, "Error opening file %s\n", argv[i]);
			return 1;
		}
	}
	
	
	free(hdr_block);
	return 0;
}

si4 parse_input_date(si1* datestr, si1* timestr, DATETIME *dtime)
{
    si1 *strPointer, *dayptr, *yrptr, *minptr, *secptr;
	
    if ((*datestr & *timestr)==0) {
		fprintf(stderr, "[%s] Error: date and time values must be provided\n", __FUNCTION__);
		return(1);
	}
	
	//get uutc time from pieces of date/time strings - hard code central time zone
	strPointer = strrchr(datestr, '/');
	if (strPointer != NULL) {
		*strPointer = 0; yrptr = strPointer+1;
		dtime->year = atof(yrptr);
	}
	strPointer = strrchr(datestr, '/');
	if (strPointer != NULL) {
		*strPointer = 0; dayptr = strPointer+1;
		dtime->day = atof(dayptr);
	}
	dtime->month = atof(datestr);
    
	strPointer = strrchr(timestr, ':');
	if (strPointer != NULL) {
		*strPointer = 0; secptr = strPointer+1;
		dtime->seconds = atof(secptr);
	}	
	strPointer = strrchr(timestr, ':');
	if (strPointer != NULL) {
		*strPointer = 0; minptr = strPointer+1;
		dtime->minute = atof(minptr);
	}
	dtime->hour = atof(timestr);
		
    
    return 0;
}

ui8 uutc_time_from_date(char *tz, sf8 yr, sf8 mo, sf8 dy, sf8 hr, sf8 mn, sf8 sc, ui8 *uutc_time)
{
	struct tm	tm;
	time_t		UTC_secs;
	long		gm_offset;
	char		timestr[30];
	
	tm.tm_sec = (int) sc;
	tm.tm_min = (int) mn;
	tm.tm_hour = (int) hr;
	tm.tm_mday = (int) dy;
	tm.tm_mon = (int) (mo - 1.0);
	tm.tm_year = (int) (yr - 1900.0);
	tm.tm_zone = tz;
	
	switch (tz[0]) {
		case 'E': gm_offset = -5; break;
		case 'C': gm_offset = -6; break;
		case 'M': gm_offset = -7; break;
		case 'P': gm_offset = -8; break;
		default:
			fprintf(stderr, "Unrecognized timezone");
			return 0;
	}	
	if (tz[1] == 'D') {
		gm_offset -= 1;
		tm.tm_isdst = 1;
	}
	tm.tm_gmtoff = gm_offset * 3600;
	
	tzset();
	fflush(stdout);
	//	fprintf(stdout, "tm_hr %d\ttm_gmtoff %d\n", tm.tm_hour, tm.tm_gmtoff);
	UTC_secs = mktime(&tm);
	fprintf(stdout, "time %s", ctime_r(&UTC_secs, timestr));
	
	*uutc_time = (unsigned long long) (UTC_secs - (int) sc) * 1000000;
	*uutc_time += (unsigned long long) ((sc * 1000000.0) + 0.5);
	
	return *uutc_time;
}