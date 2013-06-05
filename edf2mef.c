/*
 
 *  edf2mef.c
 
 Program to read European data format (EDF) and save data in mef format
 
 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "mef.h"
#include "edf_header.h"

int main (int argc, const char * argv[]) {
	int  f, numChannels, l, edfHeaderLength, varHeaderOffset, byte_offset;
	int *data, year, dl, verbose, *data_len, *cum_data_len, max_data_len, numFiles, edfblocks, n_edf_records;
	ui8 nr, block_hdr_time, discont, total_record_len, i, j, k, c;
	sf8 final_record_fraction, physical_min, physical_max, digital_min, digital_max, temp_dbl;
	signed short int *edf_data;
	ui8 inDataLength, RED_block_size;
	char subject_password[32], session_password[32], data_password[32], path[200], temp_str[200], temp_char;
	char *edf_header, *dot, *ubar, discontinuity_flag, *c_ptr;
	ui1 *out_data, file_hdr[MEF_HEADER_LENGTH], data_key[ENCRYPTION_BLOCK_BYTES];
	struct tm *hdrtime;
	time_t rawtime;
	FILE *fp, **out_fp;
	MEF_HEADER_INFO header, *hdr_array;
	RED_BLOCK_HDR_INFO RED_bk_hdr;
	INDEX_DATA *toc_array;


	if (argc < 2)
	{
		(void) printf("USAGE: %s file_name(s) [options]\n", argv[0]);
		(void) printf("Options:\n \t-v    \t\tverbose\n");
		(void) printf("\t-sub  \tsubject password\n");
		(void) printf("\t-ses  \tsession password\n");
		(void) printf("\t-n  \tnumber of EDF blocks per MEF blocks\n");
		
		return(1);
	}
	
	//defaults
	verbose = 0; 
	edfblocks = 1;
	memset(data_password, 0, 32);
	memset(subject_password, 0, 32);
	memset(session_password, 0, 32);
	memset(file_hdr, 0, MEF_HEADER_LENGTH);
	
	numFiles = argc-1;
	
	//parse options
	for (i = 1; i < argc; i++)
	{
		if (*argv[i] == '-') {
			if(strcmp(argv[i], "-sub")==0) {
				sprintf(subject_password, "%s", argv[i + 1]);
				numFiles -=2; 
			}
			if(strcmp(argv[i], "-ses")==0) {
				sprintf(session_password, "%s", argv[i + 1]);
				numFiles -= 2;
			}
			if(argv[i][1]=='v') {
			   verbose=1;
			   numFiles--;
			}
			if(argv[i][1]=='n') {
				edfblocks=atoi(argv[i+1]);
				numFiles-=2;
			}
		}
	}
	
	if(numFiles==0) {
		fprintf(stderr, "No files to convert\n\n");
		return(1);
	}
	
	
	for (f=1; f<=numFiles; f++) {
		fprintf(stdout, "Converting edf file %s...\n", argv[f]);
		fp = fopen(argv[f], "r");
		if (fp == NULL) {
			fprintf(stderr, "Error opening file %s\n", argv[f]);
			return 1;
		}
		fseek(fp, EDF_HEADER_BYTES_OFFSET, SEEK_SET);
		fscanf(fp, "%d", &edfHeaderLength);	

		edf_header = (char *)calloc(edfHeaderLength, sizeof(char));
		fseek(fp, 0, SEEK_SET);
		nr = fread(edf_header, sizeof(char), edfHeaderLength, fp);
		
		//initialize mef header
		init_hdr_struct(&header);
		(void )generate_unique_ID(header.session_unique_ID);
		header.block_header_length = BLOCK_HEADER_BYTES;
		if (*session_password) strcpy(header.session_password, session_password);
		
		
		memcpy(header.institution, (edf_header + EDF_LOCAL_RECORDING_INFO_OFFSET), EDF_LOCAL_RECORDING_INFO_LENGTH);
		memcpy(temp_str, (edf_header + EDF_NUMBER_OF_SIGNALS_OFFSET), EDF_NUMBER_OF_SIGNALS_LENGTH);
		temp_str[EDF_NUMBER_OF_SIGNALS_LENGTH]=0;
		sscanf(temp_str, "%d", &numChannels);
		
		if (numChannels < 1) {
			fprintf(stderr, "Error: %d channels found in EDF file\n", numChannels);
			return(1);
		}
		
		if (verbose) printf("%d Channels found \n", numChannels);
		
		//allocate array of headers for output files
		hdr_array = (MEF_HEADER_INFO *)calloc(sizeof(MEF_HEADER_INFO), numChannels);
		out_fp = (FILE **)calloc(sizeof(FILE*), numChannels);
		data_len = (int *) calloc(sizeof(int), numChannels);
		cum_data_len = (int *) calloc(sizeof(int), numChannels);
		
		if (hdr_array==NULL || out_fp==NULL || data_len==NULL) {
			fprintf(stderr, "Malloc error near %d\n", __LINE__);
			return(1);
		}
		
		memcpy(temp_str, (edf_header + EDF_NUMBER_OF_DATA_RECORDS_OFFSET), EDF_NUMBER_OF_DATA_RECORDS_LENGTH);
		temp_str[EDF_NUMBER_OF_DATA_RECORDS_LENGTH]=0;
		sscanf(temp_str, "%d", &n_edf_records);
		header.number_of_index_entries = n_edf_records / edfblocks;
		toc_array = (INDEX_DATA*)calloc(sizeof(INDEX_DATA), header.number_of_index_entries);
		
		memcpy(temp_str, (edf_header + EDF_DATA_RECORD_DURATION_OFFSET), EDF_DATA_RECORD_DURATION_LENGTH);
		temp_str[EDF_DATA_RECORD_DURATION_LENGTH]=0;
		sscanf(temp_str, "%lf", &temp_dbl); 
		header.block_interval = edfblocks * temp_dbl * 1000000;
		
		/// RECORDING TIMES ///
		time(&rawtime);
		hdrtime = localtime(&rawtime); //initialize to current local time - this also allocates the tm struct
		memcpy(temp_str, (edf_header + EDF_START_DATE_OFFSET), EDF_START_DATE_LENGTH);
		temp_str[EDF_START_DATE_LENGTH]=0;
		sscanf(temp_str, "%d.%d.%d", &(hdrtime->tm_mday), &(hdrtime->tm_mon), &year);
		if (year > 70) year += 1900;
		else year += 2000;
		hdrtime->tm_year = year - 1900;
		hdrtime->tm_mon--; //tm struct expects months elapsed since January
		//parse temp_str to get recording start date
		
		memcpy(temp_str, (edf_header + EDF_START_TIME_OFFSET), EDF_START_TIME_LENGTH);
		temp_str[EDF_START_TIME_LENGTH]=0;
		sscanf(temp_str, "%d.%d.%d", &(hdrtime->tm_hour), &(hdrtime->tm_min), &(hdrtime->tm_sec));
		
		header.recording_start_time = (ui8)mktime(hdrtime)*1000000;
		printf("EDF header time is: %s\n\n", asctime(hdrtime));
		
		memcpy(temp_str, (edf_header+EDF_PATIENT_INFO_OFFSET), EDF_PATIENT_INFO_LENGTH);
		temp_str[EDF_PATIENT_INFO_LENGTH]=0;
		dot = strchr(temp_str, '.');
		l = (si4)strlen(temp_str);
		ubar = strrchr(temp_str, '_');
		if (ubar == NULL || dot == NULL)
			memcpy(header.subject_third_name, temp_str, l);
		else {
			memcpy(header.subject_third_name, temp_str, dot-temp_str);
			memcpy(header.subject_first_name, dot+1, ubar - dot - 1);
			memcpy(header.subject_id, ubar+1, l - (int)(ubar-temp_str) - 1 );
		}
		sprintf(header.channel_comments, "converted from EDF");
		
		fseek(fp, 0, SEEK_END);
		inDataLength = ftell(fp) - edfHeaderLength;
		fseek(fp, edfHeaderLength, SEEK_SET);
		
		edf_data = (signed short int *) calloc(inDataLength, sizeof(si1));
		if (edf_data==NULL) {
			fprintf(stderr, "Malloc error near %d\n", __LINE__);
			return(1);
		}
		nr = fread(edf_data, 1, inDataLength, fp);
		if (nr != inDataLength) {
			fprintf(stderr, "File read error near %d\n", __LINE__);
			return(1);
		}
		
		//make output directory
		sprintf(path, "%s_mef", argv[f]);
		sprintf(temp_str, "mkdir %s", path);
		system(temp_str);
		
		//Need to read data record lengths from edf header so we know how much space to malloc
		max_data_len=0; total_record_len=0;
		for (i=0; i<numChannels; i++) {
			varHeaderOffset = EDF_FIXED_HEADER_BYTES + EDF_SAMPLES_PER_RECORD_OFFSET*numChannels;
			memcpy(temp_str, (edf_header + varHeaderOffset + EDF_SAMPLES_PER_RECORD_LENGTH*i), EDF_SAMPLES_PER_RECORD_LENGTH);
			temp_str[EDF_SAMPLES_PER_RECORD_LENGTH] =0;
			sscanf(temp_str, "%d", &data_len[i]);
			cum_data_len[i] = (si4)total_record_len; //cdl is the offset into the data record for specific chan
			total_record_len += data_len[i];
			if (edfblocks*data_len[i] > max_data_len) max_data_len = edfblocks*data_len[i];
		}
		//final_record_fraction calculates what fraction of a full data record is left for the last data record (block)
		//which could be partial.
		final_record_fraction = (sf8)(inDataLength % total_record_len)/(sf8)(total_record_len);
		//update rec end time
		
		data = (si4 *) calloc(sizeof(si4), max_data_len * edfblocks);
		out_data = (ui1 *) calloc(sizeof(si4), max_data_len * edfblocks);
		
		header.maximum_compressed_block_size=0;
		header.GMT_offset = -6.0;
		for (i=0; i<numChannels; i++) {
			//duplicate fixed header info
			memcpy(&hdr_array[i], &header, sizeof(MEF_HEADER_INFO));
			
			varHeaderOffset = EDF_FIXED_HEADER_BYTES + EDF_LABEL_OFFSET*numChannels;
			memcpy(temp_str, (edf_header + varHeaderOffset + EDF_LABEL_LENGTH*i), EDF_LABEL_LENGTH);
			temp_char = 0;
            for (k=EDF_LABEL_LENGTH-1; k>0; k--) {
                if (temp_str[k] == ' ') {
                    temp_str[k] = temp_char;
                } else {
                    temp_char='_';
                }
            }
            l=(si4)strlen(temp_str);

            if (strcmp(&temp_str[l-5], "-REF")) temp_str[l-4]=0;
			sscanf(temp_str, "%s", hdr_array[i].channel_name);
			
			sprintf(temp_str, "%s/%s.mef", path, hdr_array[i].channel_name);
			out_fp[i] = fopen(temp_str, "w");
			fwrite(file_hdr, 1, MEF_HEADER_LENGTH, out_fp[i]); //write blank header as a placeholder

			//finish reading relevant variable len edf header values, copy to mef header fields
			//need sampling frequency
			hdr_array[i].physical_channel_number = (si4)i;
			hdr_array[i].sampling_frequency = (sf8)edfblocks * 1000000.0 * (sf8)data_len[i]/(sf8)header.block_interval;
			hdr_array[i].number_of_samples = (ui8)(data_len[i] * (header.number_of_index_entries-1)) + (ui8)(final_record_fraction * (sf8)header.number_of_index_entries);
			hdr_array[i].recording_end_time = header.recording_start_time + (ui8)(1000000.0*((sf8)(hdr_array[i].number_of_samples)/hdr_array[i].sampling_frequency));
			
			varHeaderOffset = EDF_FIXED_HEADER_BYTES + EDF_PHYSICAL_MINIMUM_OFFSET*numChannels;
			memcpy(temp_str, (edf_header + varHeaderOffset + EDF_PHYSICAL_MINIMUM_LENGTH*i), EDF_PHYSICAL_MINIMUM_LENGTH);
			temp_str[EDF_PHYSICAL_MINIMUM_LENGTH]=0;
			sscanf(temp_str, "%lf", &physical_min);
			hdr_array[i].minimum_data_value = (si4)physical_min;
			
			varHeaderOffset = EDF_FIXED_HEADER_BYTES + EDF_PHYSICAL_MAXIMUM_OFFSET*numChannels;
			memcpy(temp_str, (edf_header + varHeaderOffset + EDF_PHYSICAL_MAXIMUM_LENGTH*i), EDF_PHYSICAL_MAXIMUM_LENGTH);
			temp_str[EDF_PHYSICAL_MAXIMUM_LENGTH]=0;
			sscanf(temp_str, "%lf", &physical_max);
			hdr_array[i].maximum_data_value = (si4)physical_max;

			varHeaderOffset = EDF_FIXED_HEADER_BYTES + EDF_DIGITAL_MINIMUM_OFFSET*numChannels;
			memcpy(temp_str, (edf_header + varHeaderOffset + EDF_DIGITAL_MINIMUM_LENGTH*i), EDF_DIGITAL_MINIMUM_LENGTH);
			temp_str[EDF_DIGITAL_MINIMUM_LENGTH]=0;
			sscanf(temp_str, "%lf", &digital_min);
			
			varHeaderOffset = EDF_FIXED_HEADER_BYTES + EDF_DIGITAL_MAXIMUM_OFFSET*numChannels;
			memcpy(temp_str, (edf_header + varHeaderOffset + EDF_DIGITAL_MAXIMUM_LENGTH*i), EDF_DIGITAL_MAXIMUM_LENGTH);
			temp_str[EDF_DIGITAL_MAXIMUM_LENGTH]=0;
			sscanf(temp_str, "%lf", &digital_max);
			
			varHeaderOffset = EDF_FIXED_HEADER_BYTES + EDF_PHYSICAL_DIMENSION_OFFSET*numChannels;
			memcpy(temp_str, (edf_header + varHeaderOffset + EDF_PHYSICAL_DIMENSION_LENGTH*i), EDF_PHYSICAL_DIMENSION_LENGTH);
			temp_str[EDF_PHYSICAL_DIMENSION_LENGTH]=0;
			c_ptr = temp_str; while(*c_ptr == ' ') c_ptr++;
			if (strncmp(c_ptr, "uV", 2)==0 ) hdr_array[i].voltage_conversion_factor = 1.0;
			if (strncmp(c_ptr, "mV", 2)==0 ) hdr_array[i].voltage_conversion_factor = 1000.0;
			if (hdr_array[i].voltage_conversion_factor==0) {
				fprintf(stderr, "WARNING: Physical units in EDF header for %s not recognized! MEF voltage conversion factor will be incorrect\n", hdr_array[i].channel_name);
			}
			
			//Calculate exact VCF from physical max/min and digital max/min
			hdr_array[i].voltage_conversion_factor = hdr_array[i].voltage_conversion_factor * (physical_max-physical_min)/(digital_max-digital_min);

			//read EDF samples into data buffer
			for (j=0; j<header.number_of_index_entries; j++) {
				//use previously calculated final_record_fraction to figure out how far to read
				
				if(j==header.number_of_index_entries-1) dl = (int)(data_len[i]*final_record_fraction);
				else dl = edfblocks * data_len[i];
				
				//find samples in edf file, read into buffer
				for (c=0; c<edfblocks; c++){
					for (k=0; k<data_len[i]; k++) {
						data[k+c*data_len[i]] = (si4)(*(edf_data + (j*(ui8)edfblocks + c) * total_record_len + (ui8)cum_data_len[i] + k ));
					}
				}
			
                
				//RED compress buffer
				if (j==0) discontinuity_flag = 1;
				else discontinuity_flag = 0;
				block_hdr_time = hdr_array[i].recording_start_time + (ui8)(1000000.0*(sf8)(j * data_len[i])/hdr_array[i].sampling_frequency +0.5); 
				*data_key = 0; //add support for data encryption later if needed
				RED_block_size = RED_compress_block(data, out_data, dl, block_hdr_time, (ui1)discontinuity_flag, data_key, hdr_array[i].data_encryption_used, &RED_bk_hdr);

				//update toc 
				toc_array[j].time = block_hdr_time;
				toc_array[j].sample_number = j * dl;
				toc_array[j].file_offset = ftell(out_fp[i]);
				fwrite(out_data, sizeof(si1), RED_block_size, out_fp[i]);
				
				if (RED_block_size > hdr_array[i].maximum_compressed_block_size) hdr_array[i].maximum_compressed_block_size = (ui4)RED_block_size;
				if (dl > hdr_array[i].maximum_block_length)  hdr_array[i].maximum_block_length = dl;
			}
			
			//write toc - enforce 8-byte alignment for index data
			byte_offset = ftell(out_fp[i]) % 8;
			if (byte_offset) {
				memset(data, 0, 8);
				nr = fwrite(data, 1, 8 - byte_offset, out_fp[i]);
			}
			
			//update header, write to beginning of file
			hdr_array[i].index_data_offset = ftell(out_fp[i]);
			
			//write out index data
			for (j=0; j<header.number_of_index_entries; j++) {
				fwrite(&toc_array[j].time, sizeof(ui8), 1, out_fp[i]);
				fwrite(&toc_array[j].file_offset, sizeof(ui8), 1, out_fp[i]);
				fwrite(&toc_array[j].sample_number, sizeof(ui8), 1, out_fp[i]);
			}
			
			//write discontinuity array- this is really simple for EDF
			hdr_array[i].discontinuity_data_offset = ftell(out_fp[i]);
			hdr_array[i].number_of_discontinuity_entries = 1;
			discont=1;
			fwrite(&discont, sizeof(ui8), 1, out_fp[i]);
			
			//write out updated header
			build_mef_header_block(file_hdr, &(hdr_array[i]), subject_password);		
			fseek(out_fp[i], 0, SEEK_SET);
			fwrite(file_hdr, 1, MEF_HEADER_LENGTH, out_fp[i]);
			
			fclose(out_fp[i]);
		}
		fclose(fp);
		}
	
	free(edf_header); edf_header = NULL;
	free(hdr_array); hdr_array = NULL;
	free(out_fp); out_fp=NULL;
	free(data_len); data_len=NULL;
	free(cum_data_len); cum_data_len=NULL;
	free(toc_array); toc_array=NULL;
	free(data); data = NULL;
	free(out_data); out_data = NULL;

	return 0;
	
}


