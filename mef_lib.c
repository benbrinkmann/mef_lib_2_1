//	MEF library
//	Note: need to compile with AES_encryption.c
// copyright 2012, Mayo Foundation, Rochester MN. All rights reserved
// usage and modification of the MEF source code is governed by the Apache 2.0 license

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include "mef.h"


#define EXPORT __attribute__((visibility("default")))
#define EPSILON 0.0001
#define FLOAT_EQUAL(x,y) ( ((y - EPSILON) < x) && (x <( y + EPSILON)) )



EXPORT
si4	build_mef_header_block(ui1 *encrypted_hdr_block, MEF_HEADER_INFO *hdr_struct, si1 *password)
{
	MEF_HEADER_INFO	*hs;
	si4		i, encrypted_segments, l, *rn;
	ui1		*ehbp, *ehb;
	void		AES_encrypt();

	//check inputs
	if (hdr_struct == NULL)
	{
		fprintf(stderr, "[%s] Error: NULL structure pointer passed\n", __FUNCTION__);
		return(1);
	}
	
	if (encrypted_hdr_block == NULL)
	{
		fprintf(stderr, "[%s] Error: NULL header block pointer passed\n", __FUNCTION__);
		return(1);
	}
	
	if (password == NULL)
	{
		fprintf(stderr, "[%s] Error: NULL password pointer passed\n", __FUNCTION__);
		return(1);
	}	
	
	if (check_header_block_alignment(encrypted_hdr_block, 1)) //verbose mode- error msg built into function
	{
		return(1);
	}	
	
	ehb = encrypted_hdr_block;
	hs = hdr_struct;
	
	/* check passwords */
	if (hs->subject_encryption_used) 
	{
		l = (si4) strlen(password); //entered password should be subject
		if (l >= ENCRYPTION_BLOCK_BYTES || l == 0) {
			(void) printf("\n%s: subject password error\n", __FUNCTION__);
			return(1);
		}
	}
	if (hs->session_encryption_used)
	{
		if (hs->subject_encryption_used) //subject AND session encryption used:
			l = (si4) strlen(hs->session_password);   // session password taken from the mef header structure
		else //session encryption ONLY used
		{
			l = (si4) strlen(password); //entered password should be session
			if (l == 0)
			{
				//OR - session password may just be in the header - copy to password field
				l = (si4) strlen(hs->session_password);
				if (l) strncpy2(password, hs->session_password, SESSION_PASSWORD_LENGTH); //no need for else here- l=0 case passes to error check below
			}
			else
			{
				//if session password isn't in header structure copy it there
				if (hs->session_password[0] == 0)
					strncpy2(hs->session_password, password, SESSION_PASSWORD_LENGTH);
			} //Now session password should be in both the header and the password variable
		}
		if (l >= ENCRYPTION_BLOCK_BYTES || l == 0) {
			(void) printf("\n%s: session password error\n", __FUNCTION__);
			return(1);
		}
	}
	
	if (hs->subject_encryption_used || hs->session_encryption_used) {
		/* fill header with random numbers */
		//srandomdev();
		srand(time(NULL));
		rn = (si4 *) ehb;
		for (i = MEF_HEADER_LENGTH / 4; i--;)
			*rn++ = (si4)random();
	}
	
	/* build unencrypted block */
	strncpy2((si1 *) (ehb + INSTITUTION_OFFSET), hs->institution, INSTITUTION_LENGTH);
	strncpy2((si1 *) (ehb + UNENCRYPTED_TEXT_FIELD_OFFSET), hs->unencrypted_text_field, UNENCRYPTED_TEXT_FIELD_LENGTH);	
	sprintf((si1 *) (ehb + ENCRYPTION_ALGORITHM_OFFSET), "%d-bit AES", ENCRYPTION_BLOCK_BITS);	
	*((ui1 *) (ehb + SUBJECT_ENCRYPTION_USED_OFFSET)) = hs->subject_encryption_used;		
	*((ui1 *) (ehb + SESSION_ENCRYPTION_USED_OFFSET)) = hs->session_encryption_used;		
	*((ui1 *) (ehb + DATA_ENCRYPTION_USED_OFFSET)) = hs->data_encryption_used;		
	*(ehb + BYTE_ORDER_CODE_OFFSET) = hs->byte_order_code;				
//	strncpy2((si1 *) (ehb + FILE_TYPE_OFFSET), hs->file_type, FILE_TYPE_LENGTH);		
	*(ehb + HEADER_MAJOR_VERSION_OFFSET) = hs->header_version_major;	
	*(ehb + HEADER_MINOR_VERSION_OFFSET) = hs->header_version_minor;			
	memcpy(ehb + SESSION_UNIQUE_ID_OFFSET, hs->session_unique_ID, SESSION_UNIQUE_ID_LENGTH);
	*((ui2 *) (ehb + HEADER_LENGTH_OFFSET)) = hs->header_length;
	
	/* build subject encrypted block */
	strncpy2((si1 *) (ehb + SUBJECT_FIRST_NAME_OFFSET), hs->subject_first_name, SUBJECT_FIRST_NAME_LENGTH);	
	strncpy2((si1 *) (ehb + SUBJECT_SECOND_NAME_OFFSET), hs->subject_second_name, SUBJECT_SECOND_NAME_LENGTH);
	strncpy2((si1 *) (ehb + SUBJECT_THIRD_NAME_OFFSET), hs->subject_third_name, SUBJECT_THIRD_NAME_LENGTH);
	strncpy2((si1 *) (ehb + SUBJECT_ID_OFFSET), hs->subject_id, SUBJECT_ID_LENGTH);
	
	if (hs->session_encryption_used && hs->subject_encryption_used)
		strncpy2((si1 *) (ehb + SESSION_PASSWORD_OFFSET), hs->session_password, SESSION_PASSWORD_LENGTH);
	else
		*(si1 *) (ehb + SESSION_PASSWORD_OFFSET) = 0;
	
	/* apply subject encryption to subject block */
	if (hs->subject_encryption_used) {
		//copy subject password into validation field in pascal format string
		l = (ui1) strlen(password);
		*(ehb + SUBJECT_VALIDATION_FIELD_OFFSET) = l;
		memcpy(ehb + SUBJECT_VALIDATION_FIELD_OFFSET + 1, password, l);  //memcpy doesn't add a trailing zero		
		
		encrypted_segments = SUBJECT_ENCRYPTION_LENGTH / ENCRYPTION_BLOCK_BYTES;
		ehbp = ehb + SUBJECT_ENCRYPTION_OFFSET;
		for (i = encrypted_segments; i--;) {
			AES_encrypt(ehbp, ehbp, password);
			ehbp += ENCRYPTION_BLOCK_BYTES;
		}
	}
	
	/* build session encrypted block */
	*((ui8 *) (ehb + NUMBER_OF_SAMPLES_OFFSET)) = hs->number_of_samples;
	strncpy2((si1 *) (ehb + CHANNEL_NAME_OFFSET), hs->channel_name, CHANNEL_NAME_LENGTH);	
	*((ui8 *) (ehb + RECORDING_START_TIME_OFFSET)) = hs->recording_start_time;
	*((ui8 *) (ehb + RECORDING_END_TIME_OFFSET)) = hs->recording_end_time;
	*((sf8 *) (ehb + SAMPLING_FREQUENCY_OFFSET)) = hs->sampling_frequency;	
	*((sf8 *) (ehb + LOW_FREQUENCY_FILTER_SETTING_OFFSET)) = hs->low_frequency_filter_setting;
	*((sf8 *) (ehb + HIGH_FREQUENCY_FILTER_SETTING_OFFSET)) = hs->high_frequency_filter_setting;
	*((sf8 *) (ehb + NOTCH_FILTER_FREQUENCY_OFFSET)) = hs->notch_filter_frequency;
	*((sf8 *) (ehb + VOLTAGE_CONVERSION_FACTOR_OFFSET)) = hs->voltage_conversion_factor;	
	strncpy2((si1 *) (ehb + ACQUISITION_SYSTEM_OFFSET), hs->acquisition_system, ACQUISITION_SYSTEM_LENGTH);
	strncpy2((si1 *) (ehb + CHANNEL_COMMENTS_OFFSET), hs->channel_comments, CHANNEL_COMMENTS_LENGTH);
	strncpy2((si1 *) (ehb + STUDY_COMMENTS_OFFSET), hs->study_comments, STUDY_COMMENTS_LENGTH);
	*((si4 *) (ehb + PHYSICAL_CHANNEL_NUMBER_OFFSET)) = hs->physical_channel_number;
	strncpy2((si1 *) (ehb + COMPRESSION_ALGORITHM_OFFSET), hs->compression_algorithm, COMPRESSION_ALGORITHM_LENGTH);
	*((ui4 *) (ehb + MAXIMUM_COMPRESSED_BLOCK_SIZE_OFFSET)) = hs->maximum_compressed_block_size;
	*((ui8 *) (ehb + MAXIMUM_BLOCK_LENGTH_OFFSET)) = hs->maximum_block_length;
	*((ui8 *) (ehb + BLOCK_INTERVAL_OFFSET)) = hs->block_interval;
	*((si4 *) (ehb + MAXIMUM_DATA_VALUE_OFFSET)) = hs->maximum_data_value;
	*((si4 *) (ehb + MINIMUM_DATA_VALUE_OFFSET)) = hs->minimum_data_value;
	*((ui8 *) (ehb + INDEX_DATA_OFFSET_OFFSET)) = hs->index_data_offset;
	*((ui8 *) (ehb + NUMBER_OF_INDEX_ENTRIES_OFFSET)) = hs->number_of_index_entries;
	*((ui2 *) (ehb + BLOCK_HEADER_LENGTH_OFFSET)) = hs->block_header_length;
    *((sf4 *) (ehb + GMT_OFFSET_OFFSET)) = hs->GMT_offset;
    *((ui8 *) (ehb + DISCONTINUITY_DATA_OFFSET_OFFSET)) = hs->discontinuity_data_offset;
    *((ui8 *) (ehb + NUMBER_OF_DISCONTINUITY_ENTRIES_OFFSET)) = hs->number_of_discontinuity_entries;
    memcpy(ehb + FILE_UNIQUE_ID_OFFSET, hs->file_unique_ID, FILE_UNIQUE_ID_LENGTH);
    strncpy2((si1 *) (ehb + ANONYMIZED_SUBJECT_NAME_OFFSET), hs->anonymized_subject_name, ANONYMIZED_SUBJECT_NAME_LENGTH);
    *((ui4 *) (ehb + HEADER_CRC_OFFSET)) = hs->header_crc;
	
	// apply session encryption to session block
	if (hs->session_encryption_used) {
		//copy session password into password validation field in pascal format string
		l = (ui1) strlen(hs->session_password);
		*(ehb + SESSION_VALIDATION_FIELD_OFFSET) = l;
		memcpy(ehb + SESSION_VALIDATION_FIELD_OFFSET + 1, hs->session_password, l);  //memcpy doesn't add a trailing zero		
		
		encrypted_segments = SESSION_ENCRYPTION_LENGTH / ENCRYPTION_BLOCK_BYTES;
		ehbp = ehb + SESSION_ENCRYPTION_OFFSET;
		for (i = encrypted_segments; i--;) {
			AES_encrypt(ehbp, ehbp, hs->session_password);
			ehbp += ENCRYPTION_BLOCK_BYTES;
		}
	}
		
	return(0);
}


EXPORT
si4	read_mef_header_block(ui1 *header_block, MEF_HEADER_INFO *header_struct, si1 *password)
{
	MEF_HEADER_INFO	*hs;
	si4		i, privileges, encrypted_segments, session_is_readable, subject_is_readable;
	si1		*encrypted_string;
	ui1		*hb, *dhbp, dhb[MEF_HEADER_LENGTH];
	si1		dummy;
	void	AES_decrypt();

	
	//check inputs
	if (header_struct == NULL)
	{
		fprintf(stderr, "[%s] Error: NULL structure pointer passed\n", __FUNCTION__);
		return(1);
	}
	
	if (header_block == NULL)
	{
		fprintf(stderr, "[%s] Error: NULL header block pointer passed\n", __FUNCTION__);
		return(1);
	}
	
	if (check_header_block_alignment(header_block, 1)) //verbose mode- error msg included in function
		return(1);

	hb = header_block;
	hs = header_struct;
	subject_is_readable = 0; session_is_readable = 0;
	encrypted_string = "encrypted";
	
	/* check to see if encryption algorithm matches that assumed by this function */
	(void) sprintf((si1 *) dhb, "%d-bit AES", ENCRYPTION_BLOCK_BITS);
	if (strcmp((si1 *) hb + ENCRYPTION_ALGORITHM_OFFSET, (si1 *) dhb)) {
		(void) fprintf(stderr, "%s: unknown encryption algorithm\n", __FUNCTION__);
		return(1);
	}

	memcpy(dhb, header_block, MEF_HEADER_LENGTH);
	memset(header_struct, 0, sizeof(MEF_HEADER_INFO));
	
	//read unencrypted fields
	strncpy2(hs->institution, (si1 *) (dhb + INSTITUTION_OFFSET), INSTITUTION_LENGTH);
	strncpy2(hs->unencrypted_text_field, (si1 *) (dhb + UNENCRYPTED_TEXT_FIELD_OFFSET), UNENCRYPTED_TEXT_FIELD_LENGTH);
	strncpy2(hs->encryption_algorithm, (si1 *) (dhb + ENCRYPTION_ALGORITHM_OFFSET), ENCRYPTION_ALGORITHM_LENGTH);
	hs->byte_order_code = *(dhb + BYTE_ORDER_CODE_OFFSET);
	hs->header_version_major = *(dhb + HEADER_MAJOR_VERSION_OFFSET);
	hs->header_version_minor = *(dhb + HEADER_MINOR_VERSION_OFFSET);
	for(i=0; i<SESSION_UNIQUE_ID_LENGTH; i++)
		hs->session_unique_ID[i] = *(dhb + SESSION_UNIQUE_ID_OFFSET + i*sizeof(ui1));
	
	if (hs->byte_order_code ^ cpu_endianness()) 
		hs->header_length = rev_ui2(*((ui2 *) (dhb + HEADER_LENGTH_OFFSET)));
	else
		hs->header_length = *((ui2 *) (dhb + HEADER_LENGTH_OFFSET));
	
	hs->subject_encryption_used = *(dhb + SUBJECT_ENCRYPTION_USED_OFFSET);
	hs->session_encryption_used = *(dhb + SESSION_ENCRYPTION_USED_OFFSET);
	hs->data_encryption_used = *(dhb + DATA_ENCRYPTION_USED_OFFSET);
	
		
	if(hs->subject_encryption_used==0) subject_is_readable = 1;
	if(hs->session_encryption_used==0) session_is_readable = 1;
	
	if (password == NULL)
	{
		password = &dummy;
		*password = 0;
		privileges = 0;
	}
	else if (hs->subject_encryption_used || hs->session_encryption_used)
	{
		// get password privileges
		privileges = validate_password(hb, password);
		if ( (privileges==0) && (password[0]!=0) ) { 
			(void) fprintf(stderr, "%s: unrecognized password %s\n", __FUNCTION__, password);
		}
	}
	

	if (hs->subject_encryption_used && (privileges == 1)) //subject encryption case
	{
		//decrypt subject encryption block, fill in structure fields
		encrypted_segments = SUBJECT_ENCRYPTION_LENGTH / ENCRYPTION_BLOCK_BYTES;
		dhbp = dhb + SUBJECT_ENCRYPTION_OFFSET;
		for (i = encrypted_segments; i--;) 
		{
			AES_decrypt(dhbp, dhbp, password);
			dhbp += ENCRYPTION_BLOCK_BYTES;
		}
		subject_is_readable = 1;
	}
	
	if(subject_is_readable) {
		strncpy2(hs->subject_first_name, (si1 *) (dhb + SUBJECT_FIRST_NAME_OFFSET), SUBJECT_FIRST_NAME_LENGTH);
		strncpy2(hs->subject_second_name, (si1 *) (dhb + SUBJECT_SECOND_NAME_OFFSET), SUBJECT_SECOND_NAME_LENGTH);
		strncpy2(hs->subject_third_name, (si1 *) (dhb + SUBJECT_THIRD_NAME_OFFSET), SUBJECT_THIRD_NAME_LENGTH);
		strncpy2(hs->subject_id, (si1 *) (dhb + SUBJECT_ID_OFFSET), SUBJECT_ID_LENGTH);
		if (hs->session_encryption_used && hs->subject_encryption_used ) //if both subject and session encryptions used, session password should be in hdr
			strncpy2(hs->session_password, (si1 *) (dhb + SESSION_PASSWORD_OFFSET), SESSION_PASSWORD_LENGTH);
		else if (hs->session_encryption_used)
			strncpy2(hs->session_password, password, SESSION_PASSWORD_LENGTH);
	} 
	else { 
		//subject encryption used but not decoded
		strncpy2(hs->subject_first_name, encrypted_string, SUBJECT_FIRST_NAME_LENGTH);
		strncpy2(hs->subject_second_name, encrypted_string, SUBJECT_SECOND_NAME_LENGTH);
		strncpy2(hs->subject_third_name, encrypted_string, SUBJECT_THIRD_NAME_LENGTH);
		strncpy2(hs->subject_id, encrypted_string, SUBJECT_ID_LENGTH);
		strncpy2(hs->session_password, password, SESSION_PASSWORD_LENGTH); //session password must be passed in if no subject encryption used
	}
		
	if (hs->session_encryption_used && privileges > 0)
	{
		// decrypt session password encrypted fields 
		encrypted_segments = SESSION_ENCRYPTION_LENGTH / ENCRYPTION_BLOCK_BYTES;
		dhbp = dhb + SESSION_ENCRYPTION_OFFSET;
		for (i = encrypted_segments; i--;) 
		{
			AES_decrypt(dhbp, dhbp, hs->session_password);
			dhbp += ENCRYPTION_BLOCK_BYTES;
		}
		session_is_readable = 1;
	}
	
	if (session_is_readable)
	{
		// session password encrypted fields 
		strncpy2(hs->channel_name, (si1 *) (dhb + CHANNEL_NAME_OFFSET), CHANNEL_NAME_LENGTH);
		strncpy2(hs->acquisition_system, (si1 *) (dhb + ACQUISITION_SYSTEM_OFFSET), ACQUISITION_SYSTEM_LENGTH);
		strncpy2(hs->channel_comments, (si1 *) (dhb + CHANNEL_COMMENTS_OFFSET), CHANNEL_COMMENTS_LENGTH);
		strncpy2(hs->study_comments, (si1 *) (dhb + STUDY_COMMENTS_OFFSET), STUDY_COMMENTS_LENGTH);
		strncpy2(hs->compression_algorithm, (si1 *) (dhb + COMPRESSION_ALGORITHM_OFFSET), COMPRESSION_ALGORITHM_LENGTH);
		
		// reverse bytes in some fields for endian mismatch 
		if (hs->byte_order_code ^ cpu_endianness()) {
			hs->number_of_samples = rev_ui8(*((ui8 *) (dhb + NUMBER_OF_SAMPLES_OFFSET)));
			hs->recording_start_time = rev_ui8(*((ui8 *) (dhb + RECORDING_START_TIME_OFFSET)));
			hs->recording_end_time = rev_ui8(*((ui8 *) (dhb + RECORDING_END_TIME_OFFSET)));
			hs->sampling_frequency = rev_sf8(*((sf8 *) (dhb + SAMPLING_FREQUENCY_OFFSET)));
			hs->low_frequency_filter_setting = rev_sf8(*((sf8 *) (dhb + LOW_FREQUENCY_FILTER_SETTING_OFFSET)));
			hs->high_frequency_filter_setting = rev_sf8(*((sf8 *) (dhb + HIGH_FREQUENCY_FILTER_SETTING_OFFSET)));
			hs->notch_filter_frequency = rev_sf8(*((sf8 *) (dhb + NOTCH_FILTER_FREQUENCY_OFFSET)));
			hs->voltage_conversion_factor = rev_sf8(*((sf8 *) (dhb + VOLTAGE_CONVERSION_FACTOR_OFFSET)));
			hs->block_interval = rev_ui8(*((ui8 *) (dhb + BLOCK_INTERVAL_OFFSET)));
			hs->physical_channel_number = rev_si4(*((si4 *) (dhb + PHYSICAL_CHANNEL_NUMBER_OFFSET)));
			hs->maximum_compressed_block_size = rev_ui4(*((ui4 *) (dhb + MAXIMUM_COMPRESSED_BLOCK_SIZE_OFFSET)));
			hs->maximum_block_length = rev_ui8( *((ui8 *) (dhb + MAXIMUM_BLOCK_LENGTH_OFFSET)) );
			hs->maximum_data_value = rev_si4( *((si4 *) (dhb + MAXIMUM_DATA_VALUE_OFFSET)) );
			hs->minimum_data_value = rev_si4( *((si4 *) (dhb + MINIMUM_DATA_VALUE_OFFSET)) );
			hs->index_data_offset = rev_si4(*((ui8 *) (dhb + INDEX_DATA_OFFSET_OFFSET)));
			hs->number_of_index_entries = rev_si4(*((ui8 *) (dhb + NUMBER_OF_INDEX_ENTRIES_OFFSET)));
			hs->block_header_length = rev_ui2(*((ui2 *) (dhb + BLOCK_HEADER_LENGTH_OFFSET)));
            hs->GMT_offset = rev_sf4(*((sf4 *) (dhb + GMT_OFFSET_OFFSET)));
            hs->discontinuity_data_offset= rev_ui8(*((ui8 *) (dhb + DISCONTINUITY_DATA_OFFSET_OFFSET)));
            hs->number_of_discontinuity_entries = rev_ui8(*((ui8 *) (dhb + NUMBER_OF_DISCONTINUITY_ENTRIES_OFFSET)));
		} else {
			hs->number_of_samples = *((ui8 *) (dhb + NUMBER_OF_SAMPLES_OFFSET));
			hs->recording_start_time = *((ui8 *) (dhb + RECORDING_START_TIME_OFFSET));
			hs->recording_end_time = *((ui8 *) (dhb + RECORDING_END_TIME_OFFSET));
			hs->sampling_frequency = *((sf8 *) (dhb + SAMPLING_FREQUENCY_OFFSET));
			hs->low_frequency_filter_setting = *((sf8 *) (dhb + LOW_FREQUENCY_FILTER_SETTING_OFFSET));
			hs->high_frequency_filter_setting = *((sf8 *) (dhb + HIGH_FREQUENCY_FILTER_SETTING_OFFSET));
			hs->notch_filter_frequency = *((sf8 *) (dhb + NOTCH_FILTER_FREQUENCY_OFFSET));
			hs->voltage_conversion_factor = *((sf8 *) (dhb + VOLTAGE_CONVERSION_FACTOR_OFFSET));
			hs->block_interval = *((ui8 *) (dhb + BLOCK_INTERVAL_OFFSET));
			hs->physical_channel_number = *((si4 *) (dhb + PHYSICAL_CHANNEL_NUMBER_OFFSET));
			hs->maximum_compressed_block_size = *((ui4 *) (dhb + MAXIMUM_COMPRESSED_BLOCK_SIZE_OFFSET));
			hs->maximum_block_length = *((ui8 *) (dhb + MAXIMUM_BLOCK_LENGTH_OFFSET));
			hs->maximum_data_value = *((si4 *) (dhb + MAXIMUM_DATA_VALUE_OFFSET));
			hs->minimum_data_value = *((si4 *) (dhb + MINIMUM_DATA_VALUE_OFFSET));
			hs->index_data_offset = *((ui8 *) (dhb + INDEX_DATA_OFFSET_OFFSET));
			hs->number_of_index_entries = *((ui8 *) (dhb + NUMBER_OF_INDEX_ENTRIES_OFFSET));
			hs->block_header_length = *((ui2 *) (dhb + BLOCK_HEADER_LENGTH_OFFSET));
            hs->GMT_offset = *((sf4 *) (dhb + GMT_OFFSET_OFFSET));
            hs->discontinuity_data_offset= *((ui8 *) (dhb + DISCONTINUITY_DATA_OFFSET_OFFSET));
            hs->number_of_discontinuity_entries = *((ui8 *) (dhb + NUMBER_OF_DISCONTINUITY_ENTRIES_OFFSET));
		}
	}
	else {
		//session not readable - fill with encrypted strings
		strncpy2(hs->channel_name, encrypted_string, CHANNEL_NAME_LENGTH);
		strncpy2(hs->acquisition_system, encrypted_string, ACQUISITION_SYSTEM_LENGTH);
		strncpy2(hs->channel_comments, encrypted_string, CHANNEL_COMMENTS_LENGTH);
		strncpy2(hs->study_comments, encrypted_string, STUDY_COMMENTS_LENGTH);
		strncpy2(hs->compression_algorithm, encrypted_string, COMPRESSION_ALGORITHM_LENGTH);

		hs->number_of_samples = 0;
		hs->recording_start_time = 0;
		hs->recording_end_time = 0;
		hs->sampling_frequency = -1.0;
		hs->low_frequency_filter_setting = -1.0;
		hs->high_frequency_filter_setting = -1.0;
		hs->notch_filter_frequency = -1.0;
		hs->voltage_conversion_factor = 0.0;
		hs->block_interval = 0;
		hs->physical_channel_number = -1;
		hs->maximum_compressed_block_size = 0;
		hs->maximum_block_length = 0;
		hs->index_data_offset = 0;
		hs->number_of_index_entries = 0;
		hs->block_header_length = 0;
        hs->GMT_offset = 0.0;
        hs->discontinuity_data_offset=0;
        hs->number_of_discontinuity_entries = 0;
	}
    
    for(i=0; i<FILE_UNIQUE_ID_LENGTH; i++)
		hs->file_unique_ID[i] = *(dhb + FILE_UNIQUE_ID_OFFSET + i*sizeof(ui1));
    strncpy2(hs->anonymized_subject_name, (si1 *) (dhb + ANONYMIZED_SUBJECT_NAME_OFFSET), ANONYMIZED_SUBJECT_NAME_LENGTH);
    hs->header_crc = 0; // TBD: validate header integrity here?
	
	return(0);
}

//=================================================================================================================
//si4	validate_password(ui1 *header_block, si1 *password)
//
//check password for validity - returns 1 for subject password, 2 for session password, 0 for no match
//
EXPORT
si4	validate_password(ui1 *header_block, si1 *password)
{	
	ui1	decrypted_header[MEF_HEADER_LENGTH], *hbp, *dhbp;
	si1 temp_str[SESSION_PASSWORD_LENGTH];
	si4	encrypted_segments, l, i;
	void	AES_decrypt();
	
	//check for null pointers
	if (header_block == NULL)
	{
		fprintf(stderr, "[%s] Error: NULL header pointer passed\n", __FUNCTION__);
		return(1);
	}

	if (password == NULL)
	{
		fprintf(stderr, "[%s] Error: NULL string pointer passed\n", __FUNCTION__);
		return(1);
	}
	
	//check password length
	l = (si4) strlen(password);
	if (l >= ENCRYPTION_BLOCK_BYTES) {
		fprintf(stderr, "%s: Error- password length cannot exceed %d characters\n", __FUNCTION__, ENCRYPTION_BLOCK_BYTES);
		return(0);
	}
		
	// try password as subject pwd
	encrypted_segments = SUBJECT_VALIDATION_FIELD_LENGTH / ENCRYPTION_BLOCK_BYTES;
	hbp = header_block + SUBJECT_VALIDATION_FIELD_OFFSET;
	dhbp = decrypted_header + SUBJECT_VALIDATION_FIELD_OFFSET;
	for (i = encrypted_segments; i--;) {
		AES_decrypt(hbp, dhbp, password);
		hbp += ENCRYPTION_BLOCK_BYTES;
		dhbp += ENCRYPTION_BLOCK_BYTES;
	}
	
	// convert from pascal string
	dhbp = decrypted_header + SUBJECT_VALIDATION_FIELD_OFFSET;
	l = (si4) dhbp[0];
	if (l < ENCRYPTION_BLOCK_BYTES) {
		strncpy(temp_str, (const char *)(dhbp + 1), l);
		temp_str[l] = 0;
		// compare subject passwords
		if (strcmp(temp_str, password) == 0)
			return(1);
	}
	

	// try using passed password to decrypt session encrypted key
	encrypted_segments = SESSION_VALIDATION_FIELD_LENGTH / ENCRYPTION_BLOCK_BYTES;
	hbp = header_block + SESSION_VALIDATION_FIELD_OFFSET;
	dhbp = decrypted_header + SESSION_VALIDATION_FIELD_OFFSET;
	for (i = encrypted_segments; i--;) {
		AES_decrypt(hbp, dhbp, password);
		hbp += ENCRYPTION_BLOCK_BYTES;
		dhbp += ENCRYPTION_BLOCK_BYTES;
	}
	
	// convert from pascal string
	dhbp = decrypted_header + SESSION_VALIDATION_FIELD_OFFSET;
	l = (si4) dhbp[0];
	if (l < ENCRYPTION_BLOCK_BYTES) {
		strncpy(temp_str, (const char *)(dhbp + 1), l);
		temp_str[l] = 0;
		// compare session passwords
		if (strcmp(temp_str, password) == 0)
			return(2);
	}
	
	return(0);
}


//==============================================================================================
//
//	void showHeader(MEF_HEADER_INFO *headerStruct)
//

EXPORT
void showHeader(MEF_HEADER_INFO *headerStruct)
{
	si8	long_file_time;
	si1	*time_str, temp_str[256];
	int i;
	
	//check input
	if (headerStruct == NULL)
	{
		fprintf(stderr, "[%s] Error: NULL structure pointer passed\n", __FUNCTION__);
		return;
	}
	
	sprintf(temp_str, "not entered");
	if (headerStruct->institution[0]) (void) fprintf(stdout, "institution = %s\n", headerStruct->institution);
	else (void) fprintf(stdout, "institution = %s\n", temp_str);
	
	if (headerStruct->unencrypted_text_field[0]) (void) fprintf(stdout, "unencrypted_text_field = %s\n", headerStruct->unencrypted_text_field);
	else (void) fprintf(stdout, "unencrypted_text_field = %s\n", temp_str);
	
	(void) fprintf(stdout, "encryption_algorithm = %s\n", headerStruct->encryption_algorithm);
	
	if (headerStruct->byte_order_code) sprintf(temp_str, "little"); else sprintf(temp_str, "big");
	(void) fprintf(stdout, "byte_order_code = %s endian\n", temp_str);
	
	if (headerStruct->subject_encryption_used) sprintf(temp_str, "yes"); else sprintf(temp_str, "no");
	(void) fprintf(stdout, "subject_encryption_used = %s\n", temp_str);
	
	if (headerStruct->session_encryption_used) sprintf(temp_str, "yes"); else sprintf(temp_str, "no");
	(void) fprintf(stdout, "session_encryption_used = %s\n", temp_str);
	
	if (headerStruct->data_encryption_used) sprintf(temp_str, "yes"); else sprintf(temp_str, "no");
	(void) fprintf(stdout, "data_encryption_used = %s\n", temp_str);
	
	//	(void) fprintf(stdout, "file_type = %s\n", headerStruct->file_type);
	(void) fprintf(stdout, "header_version_major = %"PRIu8"\n", headerStruct->header_version_major);
	(void) fprintf(stdout, "header_version_minor = %"PRIu8"\n", headerStruct->header_version_minor);
	
	(void) fprintf(stdout, "session UID = ");
	for(i=0; i<SESSION_UNIQUE_ID_LENGTH; i++)
		(void) fprintf(stdout, "%"PRIu8" ", headerStruct->session_unique_ID[i]);
	(void) fprintf(stdout, "\n");
	
	(void) fprintf(stdout, "header_length = %"PRIu16"\n", headerStruct->header_length);
	
	sprintf(temp_str, "not entered");
	if (headerStruct->subject_first_name[0]) (void) fprintf(stdout, "subject_first_name = %s\n", headerStruct->subject_first_name);
	else (void) fprintf(stdout, "subject_first_name = %s\n", temp_str);	
	
	if (headerStruct->subject_second_name[0]) (void) fprintf(stdout, "subject_second_name = %s\n", headerStruct->subject_second_name);
	else (void) fprintf(stdout, "subject_second_name = %s\n", temp_str);
	
	if (headerStruct->subject_third_name[0]) (void) fprintf(stdout, "subject_third_name = %s\n", headerStruct->subject_third_name);
	else (void) fprintf(stdout, "subject_third_name = %s\n", temp_str);
	
	if (headerStruct->subject_id[0]) (void) fprintf(stdout, "subject_id = %s\n", headerStruct->subject_id);
	else (void) fprintf(stdout, "subject_id = %s\n", temp_str);
	
	if (headerStruct->session_password[0]) (void) fprintf(stdout, "session_password = %s\n", headerStruct->session_password);
	else (void) fprintf(stdout, "session_password = %s\n", temp_str);
	
	if (headerStruct->number_of_samples) (void) fprintf(stdout, "number_of_samples = %"PRIu64"\n", headerStruct->number_of_samples);
	else (void) fprintf(stdout, "number_of_samples = %s\n", temp_str);
	
	if (headerStruct->channel_name[0]) (void) fprintf(stdout, "channel_name = %s\n", headerStruct->channel_name);
	else (void) fprintf(stdout, "channel_name = %s\n", temp_str);
	
	long_file_time = (si8) (headerStruct->recording_start_time + 500000) / 1000000;
	time_str = ctime((time_t *) &long_file_time); time_str[24] = 0;
	if (headerStruct->recording_start_time) {
		(void) fprintf(stdout, "recording_start_time = %"PRIu64"\t(%s)\n", headerStruct->recording_start_time, time_str);
	} else
		(void) fprintf(stdout, "recording_start_time = %s  (default value: %s)\n", temp_str, time_str);
	
	long_file_time = (si8) (headerStruct->recording_end_time + 500000) / 1000000;
	time_str = ctime((time_t *) &long_file_time); time_str[24] = 0;
	if (headerStruct->recording_start_time && headerStruct->recording_end_time) {
		(void) fprintf(stdout, "recording_end_time = %"PRIu64"\t(%s)\n", headerStruct->recording_end_time, time_str);
	} else
		(void) fprintf(stdout, "recording_end_time = %s  (default value: %s)\n", temp_str, time_str);
	
	if (FLOAT_EQUAL (headerStruct->sampling_frequency, -1.0)) fprintf(stdout, "sampling_frequency = %s\n", temp_str);
	else (void) fprintf(stdout, "sampling_frequency = %lf\n", headerStruct->sampling_frequency);
	
	if (FLOAT_EQUAL (headerStruct->low_frequency_filter_setting, -1.0))  sprintf(temp_str, "not entered");
	else if (headerStruct->low_frequency_filter_setting < EPSILON) sprintf(temp_str, "no low frequency filter");
	else sprintf(temp_str, "%lf", headerStruct->low_frequency_filter_setting);
	(void) fprintf(stdout, "low_frequency_filter_setting = %s\n", temp_str);
	
	if (FLOAT_EQUAL (headerStruct->high_frequency_filter_setting, -1.0)) sprintf(temp_str, "not entered");
	else if (headerStruct->high_frequency_filter_setting < EPSILON) sprintf(temp_str, "no high frequency filter");
	else sprintf(temp_str, "%lf", headerStruct->high_frequency_filter_setting);
	(void) fprintf(stdout, "high_frequency_filter_setting = %s\n", temp_str);
	
	if (FLOAT_EQUAL (headerStruct->notch_filter_frequency, -1.0)) sprintf(temp_str, "not entered");
	else if (headerStruct->notch_filter_frequency < EPSILON) sprintf(temp_str, "no notch filter");
	else sprintf(temp_str, "%lf", headerStruct->notch_filter_frequency);
	(void) fprintf(stdout, "notch_filter_frequency = %s\n", temp_str);
	
	if (FLOAT_EQUAL(headerStruct->voltage_conversion_factor, 0.0)) sprintf(temp_str, "not entered");
	else sprintf(temp_str, "%lf", headerStruct->voltage_conversion_factor);
	(void) fprintf(stdout, "voltage_conversion_factor = %s (microvolts per A/D unit)", temp_str);
	if (headerStruct->voltage_conversion_factor < 0.0)
		(void) fprintf(stdout, " (negative indicates voltages are inverted)\n");
	else
		(void) fprintf(stdout, "\n");
	
	(void) fprintf(stdout, "block_interval = %"PRIu64" (microseconds)\n", headerStruct->block_interval);
		
	(void) fprintf(stdout, "acquisition_system = %s\n", headerStruct->acquisition_system);
	
	if(headerStruct->physical_channel_number == -1)  (void) fprintf(stdout, "physical_channel_number = %s\n", temp_str);
	else (void) fprintf(stdout, "physical_channel_number = %d\n", headerStruct->physical_channel_number);
 
	
	sprintf(temp_str, "not entered");
	if (headerStruct->channel_comments[0]) (void) fprintf(stdout, "channel_comments = %s\n", headerStruct->channel_comments);
	else (void) fprintf(stdout, "channel_comments = %s\n", temp_str);
	
	if (headerStruct->study_comments[0]) (void) fprintf(stdout, "study_comments = %s\n", headerStruct->study_comments);
	else (void) fprintf(stdout, "study_comments = %s\n", temp_str);
	
	(void) fprintf(stdout, "compression_algorithm = %s\n", headerStruct->compression_algorithm);
	
	if(headerStruct->maximum_compressed_block_size) (void) fprintf(stdout, "maximum_compressed_block_size = %d\n", headerStruct->maximum_compressed_block_size);
	else fprintf(stdout, "maximum_compressed_block_size = %s\n", temp_str);
	
	if(headerStruct->maximum_block_length) (void) fprintf(stdout, "maximum_block_length = %"PRIu64"\n", headerStruct->maximum_block_length);	
	else (void) fprintf(stdout, "maximum_block_length = %s\n", temp_str);
	
	if(headerStruct->maximum_data_value != headerStruct->minimum_data_value) {
		(void) fprintf(stdout, "maximum_data_value = %d\n", headerStruct->maximum_data_value);
		(void) fprintf(stdout, "minimum_data_value = %d\n", headerStruct->minimum_data_value);	
	}
	else {
		(void) fprintf(stdout, "maximum_data_value = %s\n", temp_str);
		(void) fprintf(stdout, "minimum_data_value = %s\n", temp_str);
	}
		
	if(headerStruct->index_data_offset) (void) fprintf(stdout, "index_data_offset = %"PRIu64"\n", headerStruct->index_data_offset);
	else (void) fprintf(stdout, "index_data_offset = %s\n", temp_str);
	
	if(headerStruct->number_of_index_entries) (void) fprintf(stdout, "number_of_index_entries = %"PRIu64"\n", headerStruct->number_of_index_entries);
	else (void) fprintf(stdout, "number_of_index_entries = %s\n", temp_str);

	if(headerStruct->block_header_length) (void) fprintf(stdout, "block_header_length = %d\n", headerStruct->block_header_length);
	else (void) fprintf(stdout, "block_header_length = %s\n", temp_str);
    
    if (headerStruct->header_version_minor > 0)
    {
        (void) fprintf(stdout, "GMT_offset = %f\n", headerStruct->GMT_offset);

        if(headerStruct->discontinuity_data_offset) (void) fprintf(stdout, "discontinuity_data_offset = %"PRIu64"\n", headerStruct->discontinuity_data_offset);
        else (void) fprintf(stdout, "discontinuity_data_offset = %s\n", temp_str);
    
        (void) fprintf(stdout, "number_of_discontinuity_entries = %"PRIu64"\n", headerStruct->number_of_discontinuity_entries);
    
        (void) fprintf(stdout, "file UID = ");
        for(i=0; i<FILE_UNIQUE_ID_LENGTH; i++)
            (void) fprintf(stdout, "%u ", headerStruct->file_unique_ID[i]);
        (void) fprintf(stdout, "\n");
    
        if (headerStruct->anonymized_subject_name[0]) (void) fprintf(stdout, "anonymized_subject_name = %s\n", headerStruct->anonymized_subject_name);
        else (void) fprintf(stdout, "anonymized_subject_name= %s\n", temp_str);
    }
    
	return;
}


EXPORT
ui8 generate_unique_ID(ui1 *array)
{
    static ui1 first_time = 1; 
	ui8 long_output = 0;
	si4 i;
	
	if (array == NULL) 
	{
		array = calloc(SESSION_UNIQUE_ID_LENGTH, sizeof(ui1));
	}
    
    if (first_time)
    {
        srandom(time(NULL));
        first_time = 0;
    }
    
	for (i=0; i<SESSION_UNIQUE_ID_LENGTH; i++) 
	{
		array[i] = (ui1)(random() % 255);
		long_output += array[i] >> i; 
	}
	
	return (long_output);
}


EXPORT
void set_hdr_unique_ID(MEF_HEADER_INFO *header, ui1 *array)
{
	//check input
	if (header == NULL)
	{
		fprintf(stderr, "[%s] Error: NULL structure pointer passed\n", __FUNCTION__);
		return;
	}
	
	if (array == NULL) //generate new uid
	{
		array = calloc(SESSION_UNIQUE_ID_LENGTH, sizeof(ui1));
		(void)generate_unique_ID(array);
	}
	
	memcpy(header->session_unique_ID, array, SESSION_UNIQUE_ID_LENGTH);
	return;
}


EXPORT
void set_block_hdr_unique_ID(ui1 *block_header, ui1 *array)
{
	
	if (array == NULL) //generate new uid
	{
		array = calloc(SESSION_UNIQUE_ID_LENGTH, sizeof(ui1));
		(void)generate_unique_ID(array);
	}
	
	memcpy((block_header + SESSION_UNIQUE_ID_OFFSET), array, SESSION_UNIQUE_ID_LENGTH);
	return;
}


EXPORT
ui8 set_session_unique_ID(char *file_name, ui1 *array)
{
	FILE *mef_fp;
	si4 read_mef_header_block(), validate_password();
	
	
	//Open file
	mef_fp = fopen(file_name, "r+");
	if (mef_fp == NULL) {
		fprintf(stderr, "%s: Could not open file %s\n", __FUNCTION__, file_name);
		return(1);
	}
	

	if (array == NULL) {	
		array = calloc(SESSION_UNIQUE_ID_LENGTH, sizeof(ui1));
		(void)generate_unique_ID(array);
	}
	
	//write file unique ID to header
	fseek(mef_fp, SESSION_UNIQUE_ID_OFFSET, SEEK_SET);
	fwrite(array, sizeof(ui1), SESSION_UNIQUE_ID_LENGTH, mef_fp);
	
	fseek(mef_fp, 0, SEEK_END);
		
	fclose(mef_fp);
	
	return(0);
}


EXPORT
si4 check_header_block_alignment(ui1 *header_block, si4 verbose)
{
	if ((ui8) header_block % 8) {
		if (verbose)
			(void) fprintf(stderr, "Header block is not 8 byte boundary aligned [use malloc() rather than heap declaration] ==> exiting\n");
		return(1);
	}
	
	return(0);
}


EXPORT
void strncpy2(si1 *s1, si1 *s2, si4 n)
{
	si4      len;

	for (len = 1; len < n; ++len) {
		if (*s1++ = *s2++)
			continue;
		return;
	}
	s1[n-1] = 0;

	return;
}


void init_hdr_struct(MEF_HEADER_INFO *header)
{	
	
	memset(header, 0, sizeof(MEF_HEADER_INFO));
	
	header->header_version_major=HEADER_MAJOR_VERSION;
	header->header_version_minor=HEADER_MINOR_VERSION;
	header->header_length=MEF_HEADER_LENGTH;
	header->block_header_length=BLOCK_HEADER_BYTES;
	
	sprintf(header->compression_algorithm, "Range Encoded Differences (RED)");
	sprintf(header->encryption_algorithm,  "AES %d-bit", ENCRYPTION_BLOCK_BITS);
	
	if (cpu_endianness())
		header->byte_order_code = 1;
	else
		header->byte_order_code = 0;
	
	return; 
}

EXPORT
si4	write_mef(si4 *samps, MEF_HEADER_INFO *mef_header, ui8 len, si1 *out_file, si1 *subject_password)
{
	ui1 *header, byte_padding[8], discontinuity_flag;
	ui1	*compressed_buffer, *cbp;
	si1 encryption_key[240];
	si4	sl, max_value, min_value, byte_offset, *sp;
	ui4 samps_per_block;
	si8	i;
	ui8 curr_time, nr, samps_left, index_data_offset, dataCounter;
	ui8 entryCounter, num_blocks, max_block_size, RED_block_size;
	FILE	*fp;
	RED_BLOCK_HDR_INFO RED_bk_hdr;
	INDEX_DATA *index_block, *ip;
	void	AES_KeyExpansion();
	
	if ( mef_header==NULL ) {
		fprintf(stderr, "[%s] NULL header pointer passed into function\n", __FUNCTION__);
		return(1);
	}
	
	header = calloc(sizeof(ui1), (size_t)MEF_HEADER_LENGTH);
	curr_time = mef_header->recording_start_time;
	
	//Check input header values for validity
	if ( mef_header->sampling_frequency < 0.001) {
		fprintf(stderr, "[%s] Improper sampling frequency (%lf Hz) in header %s\n", __FUNCTION__,  mef_header->sampling_frequency, 
				mef_header->channel_name);
		return(1);
	}
	
	if ( mef_header->block_interval < 0.001) {
		fprintf(stderr, "[%s] Improper block interval (%"PRIu64" microseconds) in header %s\n", __FUNCTION__,  mef_header->block_interval, 
				mef_header->channel_name);
		return(1);
	}	
	samps_per_block = (ui4)((sf8)mef_header->block_interval * mef_header->sampling_frequency/ 1000000.0); 
	
	if (samps_per_block < 1) {
		fprintf(stderr, "[%s] Improper header info- must encode 1 or more samples in each block\n", __FUNCTION__);
		return(1);
	}
	if (samps_per_block > mef_header->number_of_samples) {
		fprintf(stderr, "[%s] Improper header info- samples per block %u greater than total entries %"PRIu64" for %s\n", __FUNCTION__, samps_per_block,
				mef_header->number_of_samples, mef_header->channel_name);
		return(1);
	}
	num_blocks = ceil( (sf8)len / (sf8)samps_per_block  );
	
	if (num_blocks < 1) {
		fprintf(stderr, "[%s] Improper header info- must encode 1 or more blocks\n", __FUNCTION__);
		return(1);
	}
	
	mef_header->number_of_samples = (ui8) len;  //number of samples may be different from original file
	mef_header->maximum_block_length = samps_per_block;
	
	encryption_key[0] = 0;
	if (mef_header->data_encryption_used)
		AES_KeyExpansion(4, 10, encryption_key, mef_header->session_password); 
	
	
	index_block = (INDEX_DATA *)calloc(num_blocks, sizeof(INDEX_DATA));
	compressed_buffer = calloc(num_blocks*samps_per_block, sizeof(si4)); //we'll assume at least 50% compression
	
	if (index_block == NULL || compressed_buffer == NULL) {
		fprintf(stderr, "[%s] malloc error\n", __FUNCTION__);
		return(1);
	}
	
	sl = (si4)strlen(out_file);
	if ((strcmp((out_file + sl - 4), ".mef"))) {
		fprintf(stderr, "no \".mef\" on input name => exiting\n");
		return(1);
	}
	fp = fopen(out_file, "w");
	if (fp == NULL) {fprintf(stderr, "Error [%s]: Can't open file %s for writing\n\n", __FUNCTION__, out_file); exit(1);}
	
	
	memset(header, 0, MEF_HEADER_LENGTH); //fill mef header space with zeros - will write real info after writing blocks and indices
	fwrite(header, 1, MEF_HEADER_LENGTH, fp);
	
	sp = samps;	
	cbp = compressed_buffer; 
	ip = index_block;
	dataCounter = MEF_HEADER_LENGTH; 
	entryCounter=0; 
	discontinuity_flag = 1;
	max_value = INT_MAX; min_value = INT_MIN; 
	max_block_size = 0;
	
	samps_left = len;
	for (i=0; i<num_blocks; i++) {
		ip->time = mef_header->recording_start_time + i * mef_header->block_interval;
		ip->file_offset = dataCounter; 
		ip->sample_number = i * samps_per_block;
		
		if (samps_left < samps_per_block) samps_per_block = (ui4)samps_left;		
		
		RED_block_size = RED_compress_block(sp, cbp, samps_per_block, ip->time, (ui1)discontinuity_flag, encryption_key, mef_header->data_encryption_used, &RED_bk_hdr);
		
		dataCounter += RED_block_size;
		cbp += RED_block_size;
		entryCounter += RED_bk_hdr.sample_count;
		samps_left -= RED_bk_hdr.sample_count;
		sp += RED_bk_hdr.sample_count;
		ip++;
		
		if (RED_bk_hdr.max_value > max_value) max_value = RED_bk_hdr.max_value;
		if (RED_bk_hdr.min_value < min_value) min_value = RED_bk_hdr.min_value;
		if (RED_block_size > max_block_size) max_block_size = RED_block_size;
		
		discontinuity_flag = 0; //only the first block has a discontinuity		
	}
	
	//update mef header with new values
	mef_header->maximum_data_value = max_value;
	mef_header->minimum_data_value = min_value;
	mef_header->maximum_compressed_block_size = (ui4)max_block_size;
	mef_header->number_of_index_entries = num_blocks;
	
	// write mef entries
	nr = fwrite(compressed_buffer, sizeof(si1), (size_t) dataCounter - MEF_HEADER_LENGTH, fp); 
	if (nr != dataCounter - MEF_HEADER_LENGTH) { fprintf(stderr, "Error writing file\n"); fclose(fp); return(1); }
	
	//byte align index data if needed
	index_data_offset = ftell(fp);
	byte_offset = (si4)(index_data_offset % 8);
	if (byte_offset) {
		memset(byte_padding, 0, 8);
		fwrite(byte_padding, sizeof(ui1), 8 - byte_offset, fp);
		index_data_offset += 8 - byte_offset;
	}
	mef_header->index_data_offset = index_data_offset;
	
	//write index offset block to end of file
	nr = fwrite(index_block, sizeof(INDEX_DATA), (size_t) num_blocks, fp); 
	
	//build mef header from structure
	nr = build_mef_header_block(header, mef_header, subject_password); //recycle nr
	if (nr) { fprintf(stderr, "Error building mef header\n"); return(1); }
	
	fseek(fp, 0, SEEK_SET); //reset fp to beginning of file to write mef header
	nr = fwrite(header, sizeof(ui1), (size_t) MEF_HEADER_LENGTH, fp);
	if (nr != MEF_HEADER_LENGTH) { fprintf(stderr, "Error writing mef header\n"); return(1); }
	
	fclose(fp);
	
	free(compressed_buffer);
	free(index_block);
	
	return(0);
}

EXPORT
si4	write_mef_ind(si4 *samps, MEF_HEADER_INFO *mef_header, ui8 len, si1 *out_file, si1 *subject_password, INDEX_DATA *index_block, si4 num_blocks, ui1 *discontinuity_array)
{
	ui1 *header, byte_padding[8], *compressed_buffer, *cbp;
	si1	free_index=0, free_discont=0, encryption_key[240];
	si4	sl, max_value, min_value, byte_offset, *sp, samps_to_encode;
	ui4 samps_per_block;
	si8	i;
	ui8 curr_time, nr, samps_left, index_data_offset, dataCounter;
	ui8 entryCounter, max_block_size, RED_block_size;
	sf8 dt, ds;
	FILE	*fp;
	RED_BLOCK_HDR_INFO RED_bk_hdr;
	INDEX_DATA *ip;
	void	AES_KeyExpansion();
	
	//check inputs
	if ( mef_header==NULL ) {
		fprintf(stderr, "[%s] NULL header pointer passed into function\n", __FUNCTION__);
		return(1);
	}
	//Check input header values for validity
	if ( mef_header->sampling_frequency < 0.001 || mef_header->sampling_frequency > 1000000) {
		fprintf(stderr, "[%s] Improper sampling frequency (%lf Hz) in header %s\n", __FUNCTION__,  mef_header->sampling_frequency, 
				mef_header->channel_name);
		return(1);
	}	
	if ( mef_header->block_interval < (ui8)(2.0 * 1000000.0 / mef_header->sampling_frequency)) { //must encode at least 2 samples per block
		fprintf(stderr, "[%s] Improper block interval (%"PRIu64" microseconds) in header %s for stated sampling frequency %lf\n", __FUNCTION__,  mef_header->block_interval, mef_header->channel_name, mef_header->sampling_frequency);
		return(1);
	}

    header = calloc(sizeof(ui1), (size_t)MEF_HEADER_LENGTH);
	curr_time = mef_header->recording_start_time;
	samps_per_block = (ui4)((sf8)mef_header->block_interval * mef_header->sampling_frequency/ 1000000.0); 
	
	if (samps_per_block < 2) {
		fprintf(stderr, "[%s] Improper header info- must encode 2 or more samples in each block\n", __FUNCTION__);
		return(1);
	}
	if (samps_per_block > mef_header->number_of_samples) {
		fprintf(stderr, "[%s] Improper header info- samples per block %u greater than total entries %"PRIu64" for %s\n", __FUNCTION__, samps_per_block,
				mef_header->number_of_samples, mef_header->channel_name);
		return(1);
	}
	
	mef_header->number_of_samples = (ui8) len;  
	mef_header->maximum_block_length = samps_per_block;
	
	if (mef_header->high_frequency_filter_setting > mef_header->sampling_frequency)
		mef_header->high_frequency_filter_setting = mef_header->sampling_frequency;
	
	encryption_key[0] = 0;
	if (mef_header->data_encryption_used)
		AES_KeyExpansion(4, 10, encryption_key, mef_header->session_password); 

	sl = (si4)strlen(out_file);
	if ((strcmp((out_file + sl - 4), ".mef"))) {
		fprintf(stderr, "no \".mef\" on input name => exiting\n");
		return(1);
	}
	fp = fopen(out_file, "w");
	if (fp == NULL) {fprintf(stderr, "Error [%s]: Can't open file %s for writing\n\n", __FUNCTION__, out_file); exit(1);}
	
	memset(header, 0, MEF_HEADER_LENGTH); //fill mef header space with zeros - will write real info after writing blocks and indices
	fwrite(header, 1, MEF_HEADER_LENGTH, fp);
	
	//calculate index entries if not passed in
    if (index_block == NULL) {
        num_blocks = ceil( (sf8)len / (sf8)samps_per_block  );
        if (num_blocks < 1) {
            fprintf(stderr, "[%s] Improper header info- must encode 1 or more blocks\n", __FUNCTION__);
            return(1);
        }
        ip = index_block = (INDEX_DATA *)calloc(num_blocks, sizeof(INDEX_DATA));
		free_index = 1;
        for (i=0; i<num_blocks; i++) {
            ip->time = mef_header->recording_start_time + i * mef_header->block_interval;
            ip->sample_number = i * samps_per_block;
        }
    }
	compressed_buffer = calloc(num_blocks*samps_per_block, sizeof(si4)); 
	
	if (index_block == NULL || compressed_buffer == NULL) {
		fprintf(stderr, "[%s] malloc error %d\n", __FUNCTION__, __LINE__);
		return(1);
	}    
	
	//calculate discontinuity arry if none was passed in
	if (discontinuity_array == NULL) {
        discontinuity_array = (ui1 *)calloc(num_blocks, sizeof(ui1));
		free_discont = 1;
		if (discontinuity_array== NULL) {
			fprintf(stderr, "[%s] malloc error %d\n", __FUNCTION__, __LINE__);
			free(header);
			if (free_index) {free(index_block); index_block=NULL;}
			return(1);
		}
		discontinuity_array[0] = 1;
		for (i=1; i<num_blocks; i++) {
			ds = (sf8)(index_block[i].sample_number - index_block[i-1].sample_number);
			dt = (sf8)(index_block[i].time - index_block[i-1].time)/1000000.0;
			if (fabs(dt - ds/mef_header->sampling_frequency) > (sf8)mef_header->block_interval/(2.0*1000000.0))
				discontinuity_array[i]=1;
		}
	}
    
	max_value = INT_MIN; min_value = INT_MAX; 
	sp = samps;	
	cbp = compressed_buffer; 
	ip = index_block;
	dataCounter = MEF_HEADER_LENGTH; 
	entryCounter=0; 
	max_block_size = 0;
	
	samps_left = len;
	for (i=0; i<num_blocks; i++) {
		ip->file_offset = dataCounter; 
		
		if (i==num_blocks-1)
			samps_to_encode = mef_header->number_of_samples - index_block[i].sample_number;
		else
			samps_to_encode = index_block[i+1].sample_number - index_block[i].sample_number;

		if (samps_left < samps_to_encode) samps_to_encode = (ui4)samps_left;		
		
		RED_block_size = RED_compress_block(sp, cbp, samps_to_encode, ip->time, (ui1)discontinuity_array[i], encryption_key, mef_header->data_encryption_used, &RED_bk_hdr);
		
		dataCounter += RED_block_size;
		cbp += RED_block_size;
		entryCounter += RED_bk_hdr.sample_count;
		samps_left -= RED_bk_hdr.sample_count;
		sp += RED_bk_hdr.sample_count;
		ip++;
		
		if (RED_bk_hdr.max_value > max_value) max_value = RED_bk_hdr.max_value;
		if (RED_bk_hdr.min_value < min_value) min_value = RED_bk_hdr.min_value;
		if (RED_block_size > max_block_size) max_block_size = RED_block_size;
		if (samps_to_encode > mef_header->maximum_block_length) mef_header->maximum_block_length = samps_to_encode;
	}
	
	//update mef header with new values
	mef_header->maximum_data_value = max_value;
	mef_header->minimum_data_value = min_value;
	mef_header->maximum_compressed_block_size = (ui4)max_block_size;
	mef_header->number_of_index_entries = num_blocks;
	
	// write mef entries
	nr = fwrite(compressed_buffer, sizeof(si1), (size_t) dataCounter - MEF_HEADER_LENGTH, fp); 
	if (nr != dataCounter - MEF_HEADER_LENGTH) { fprintf(stderr, "Error writing file\n"); fclose(fp); return(1); }
	
	//byte align index data if needed
	index_data_offset = ftell(fp);
	byte_offset = (si4)(index_data_offset % 8);
	if (byte_offset) {
		memset(byte_padding, 0, 8);
		fwrite(byte_padding, sizeof(ui1), 8 - byte_offset, fp);
		index_data_offset += 8 - byte_offset;
	}
	mef_header->index_data_offset = index_data_offset;
	
	//write index offset block to end of file
	nr = fwrite(index_block, sizeof(INDEX_DATA), (size_t) num_blocks, fp); 
	
	//build mef header from structure
	nr = build_mef_header_block(header, mef_header, subject_password); //recycle nr
	if (nr) { fprintf(stderr, "Error building mef header\n"); return(1); }
	
	fseek(fp, 0, SEEK_SET); //reset fp to beginning of file to write mef header
	nr = fwrite(header, sizeof(ui1), (size_t) MEF_HEADER_LENGTH, fp);
	if (nr != MEF_HEADER_LENGTH) { fprintf(stderr, "Error writing mef header\n"); return(1); }
	
	fclose(fp);
	
	free(compressed_buffer); compressed_buffer = NULL;
	
	if (free_index) {
		free(index_block);
		index_block = NULL;
	}
	
	return(0);
}


EXPORT
si4	build_RED_block_header(ui1 *header_block, RED_BLOCK_HDR_INFO *header_struct)
{
	ui1	*ui1_p, *ui1_p2;
	ui4	block_len, comp_block_len, diff_cnts, crc, *ui4_p;
	si1 discontinuity, *si1_p;
	si4 i, max_data_value, min_data_value;
	ui8 time_value, *ui8_p;	
	ui4 calculate_compressed_block_CRC();
	
	//check inputs
	if (header_block==NULL) {
		fprintf(stderr, "[%s] NULL header block passed in\n", __FUNCTION__);
		return(1);
	}
	if (header_struct==NULL) {
		fprintf(stderr, "[%s] NULL block header structure pointer passed in\n", __FUNCTION__);
		return(1);
	}

	//perhaps this is overly cautious, but we'll copy structure values to intermediate variables to avoid
	//the possibility of overwriting the structure fields by mistake
	comp_block_len = header_struct->compressed_bytes; 
	time_value = header_struct->block_start_time;
	diff_cnts = header_struct->difference_count;
	block_len = header_struct->sample_count;
	max_data_value = header_struct->max_value; 
	min_data_value = header_struct->min_value;
	discontinuity = header_struct->discontinuity;
	
	ui4_p = (ui4*)(header_block + RED_CHECKSUM_OFFSET); //this should be unnecessary as we skip the first 4 bytes in the CRC calculation
	*ui4_p = 0;
	
	ui4_p = (ui4*)(header_block + RED_COMPRESSED_BYTE_COUNT_OFFSET);
	*ui4_p = comp_block_len;

	ui8_p = (ui8*)(header_block + RED_UUTC_TIME_OFFSET);
	*ui8_p = time_value;
	
	ui4_p = (ui4*)(header_block + RED_DIFFERENCE_COUNT_OFFSET);
	*ui4_p = diff_cnts;

	ui4_p = (ui4*)(header_block + RED_SAMPLE_COUNT_OFFSET);
	*ui4_p = block_len;

	ui1_p = (ui1*)(header_block + RED_DATA_MAX_OFFSET);
	ui1_p2 = (ui1*) &max_data_value; //encode max and min values as si3
	for (i = 0; i < 3; ++i)
		*ui1_p++ = *ui1_p2++;
	
	ui1_p = (ui1*)(header_block + RED_DATA_MIN_OFFSET);
	ui1_p2 = (ui1 *) &min_data_value; //encode max and min values as si3
	for (i = 0; i < 3; ++i) 
		*ui1_p++ = *ui1_p2++;
	
	
	si1_p = (si1*)(header_block + RED_DISCONTINUITY_OFFSET);
	*si1_p = discontinuity;
	
	//Now that all the values are copied, update the CRC
	crc = calculate_compressed_block_CRC(header_block);
	ui4_p = (ui4*)(header_block + RED_CHECKSUM_OFFSET); 
	*ui4_p = crc;

	return(0);
}

EXPORT
si4	read_RED_block_header(ui1 *header_block, RED_BLOCK_HDR_INFO *header_struct)
{
	ui1	*ib_p, *ui1_p;
	ui4	block_len, comp_block_len, diff_cnts, checksum_read;
	si1 discontinuity;
	si4 i, max_data_value, min_data_value;
	ui8 time_value;	
	
	//check inputs
	if (header_block==NULL) {
		fprintf(stderr, "[%s] NULL header block passed in\n", __FUNCTION__);
		return(1);
	}
	
	if (header_struct==NULL) {
		fprintf(stderr, "[%s] NULL block header structure pointer passed in\n", __FUNCTION__);
		return(1);
	}
		
	/*** parse block header ***/
	ib_p = header_block;

	checksum_read = *(ui4 *)(ib_p + RED_CHECKSUM_OFFSET); 
	comp_block_len = *(ui4 *)(ib_p + RED_COMPRESSED_BYTE_COUNT_OFFSET); 
	time_value = *(ui8 *)(ib_p + RED_UUTC_TIME_OFFSET);
	diff_cnts = *(ui4 *)(ib_p + RED_DIFFERENCE_COUNT_OFFSET);
	block_len = *(ui4 *)(ib_p + RED_SAMPLE_COUNT_OFFSET);
	
	max_data_value = 0; min_data_value = 0;
	
	ib_p = header_block + RED_DATA_MAX_OFFSET;
	ui1_p = (ui1 *) &max_data_value; 
	for (i = 0; i < 3; ++i) { *ui1_p++ = *ib_p++; }	
	*ui1_p++ = (*(si1 *)(ib_p-1)<0) ? -1 : 0; //sign extend
	
	ib_p = header_block + RED_DATA_MIN_OFFSET;
	ui1_p = (ui1 *) &min_data_value; 
	for (i = 0; i < 3; ++i) { *ui1_p++ = *ib_p++; }	
	*ui1_p++ = (*(si1 *)(ib_p-1)<0) ? -1 : 0; //sign extend
	
	ib_p = header_block;
	discontinuity = *(ib_p + RED_DISCONTINUITY_OFFSET);
	
	header_struct->CRC_32 = checksum_read;
	header_struct->compressed_bytes = comp_block_len;
	header_struct->block_start_time = time_value;
	header_struct->sample_count = block_len;
	header_struct->difference_count = diff_cnts;
	header_struct->max_value = max_data_value;
	header_struct->min_value = min_data_value;
	header_struct->discontinuity = discontinuity;
	
	header_struct->CRC_validated = 0; //This function performs no CRC validation
	
	return(0);
}

ui4 calculate_compressed_block_CRC(ui1 *data_block) 
{
	int i, result;
	ui4 checksum, block_len;
	RED_BLOCK_HDR_INFO bk_hdr;
	ui4 update_crc_32();
	
	if (data_block == NULL) {
		fprintf(stderr, "[%s] Error: NULL data pointer passed in\n", __FUNCTION__);
		return(1);
	}
	
	result = read_RED_block_header(data_block, &bk_hdr);
	if (result) {
		fprintf(stderr, "[%s] Error reading RED block header\n", __FUNCTION__);
		return(1);
	}
	
	block_len = bk_hdr.compressed_bytes + BLOCK_HEADER_BYTES;
	
	//calculate CRC checksum - skip first 4 bytes
	checksum = 0xffffffff;
	for (i = RED_CHECKSUM_LENGTH; i < block_len; i++) //skip first 4 bytes- don't include the CRC itself in calculation
		checksum = update_crc_32(checksum, *(data_block + i));
	
	return checksum;
}


si4 validate_mef(char *mef_filename, char *log_filename, char *password)
{
	int i, blocks_per_read;
	ui1 encr_hdr[MEF_HEADER_LENGTH], *data, logfile, bad_index;
	ui8 n, data_end, data_start, calc_end_time, num_errors;
	si8 offset, dt, ds, max_dt;
	ui4 crc, block_size;
	char message[200], *time_str;
	FILE *mfp, *lfp;
	MEF_HEADER_INFO header;
	RED_BLOCK_HDR_INFO bk_hdr;
	INDEX_DATA *indx_array;
	time_t now;
	
	blocks_per_read = 3000;
	num_errors = 0;
	bad_index = 0;
	
	if (mef_filename == NULL) {
		fprintf(stderr, "[%s] Error: NULL mef filename pointer passed in\n", __FUNCTION__);
		return(1);
	}

	//NULL or empty log_filename directs output to stdout only
	if ((log_filename == NULL)||(*log_filename==0)) {
		lfp = NULL;
		logfile = 0;
	}
	else {
		//check to see if log file exists
		logfile = 1;
		lfp = fopen(log_filename, "r");
		if (lfp != NULL)
			fprintf(stdout, "[%s] Appending to existing logfile %s\n", __FUNCTION__, log_filename);
		fclose(lfp);
		lfp = fopen(log_filename, "a+");
		if (lfp == NULL) {
			fprintf(stderr, "[%s] Error opening %s for writing\n", __FUNCTION__, log_filename);
			return(1);
		}
	}

	mfp = fopen(mef_filename, "r");
	if (mfp == NULL) {fprintf(stderr, "[%s] Error opening mef file %s\n", __FUNCTION__, mef_filename); return(1);}

	n = fread(encr_hdr, 1, MEF_HEADER_LENGTH, mfp);
	if (n != MEF_HEADER_LENGTH || ferror(mfp)) {fprintf(stderr, "[%s] Error reading mef header %s\n", __FUNCTION__, mef_filename); return(1); }
	
	//Check that this is a valid mef2 file
	if (*(ui1*)(encr_hdr + HEADER_MAJOR_VERSION_OFFSET) != 2) {fprintf(stderr, "[%s] Error: file %s does not appear to be a valid MEF file\n", __FUNCTION__, mef_filename); return(1);}
	
	n = read_mef_header_block(encr_hdr, &header, password);
	if (n) {fprintf(stderr, "[%s] Error decrypting mef header %s\n", __FUNCTION__, mef_filename); return(1);}
	
	n = fseek(mfp, header.index_data_offset, SEEK_SET);
	if (n) {fprintf(stderr, "[%s] fseek error in %s\n", __FUNCTION__, mef_filename); return(1);}
	
	indx_array = (INDEX_DATA*)calloc(header.number_of_index_entries, sizeof(INDEX_DATA));
	if (indx_array==NULL) {fprintf(stderr, "[%s] index malloc error while checking %s\n", __FUNCTION__, mef_filename); return(1); }
	
	n = fread(indx_array, sizeof(INDEX_DATA), header.number_of_index_entries, mfp);
	if (n != header.number_of_index_entries || ferror(mfp)) {fprintf(stderr, "[%s] Error reading mef index array %s\n", __FUNCTION__, mef_filename); return(1); }
	
	if (blocks_per_read > header.number_of_index_entries) 
		blocks_per_read = (int)header.number_of_index_entries;
	data = calloc(header.maximum_compressed_block_size, blocks_per_read);
	if (indx_array==NULL) {fprintf(stderr, "[%s] data malloc error while checking %s\n", __FUNCTION__, mef_filename); return(1); }

	now = time(NULL);
	time_str = ctime(&now); time_str[24]=0;
	
	sprintf(message, "\n%s: Beginning MEF validation check of file %s\n", time_str, mef_filename);
	fprintf(stdout, "%s", message);
	if (logfile) fprintf(lfp, "%s", message);	
	
//// Begin checking mef file ///
	//Check header recording times against index array
	if (header.recording_start_time != indx_array[0].time) {
		num_errors++;
		sprintf(message, "Header recording_start_time %"PRIu64" does not match index array time %"PRIu64"\n", header.recording_start_time, indx_array[0].time);
		fprintf(stdout, "%s", message);
		if (logfile) fprintf(lfp, "%s", message);
	}
	calc_end_time = header.recording_start_time + (ui8)(0.5 + 1000000.0 * (sf8)header.number_of_samples/header.sampling_frequency);
	if (header.recording_end_time < calc_end_time) {
		num_errors++;
		sprintf(message, "Header recording_end_time %"PRIu64" does not match sampling freqency and number of samples\n", header.recording_end_time);
		fprintf(stdout, "%s", message);
		if (logfile) fprintf(lfp, "%s", message);
	}
	max_dt=0;
	for (i=1; i<header.number_of_index_entries; i++) {
		offset = (si8)(indx_array[i].file_offset - indx_array[i-1].file_offset);
		if (offset > header.maximum_compressed_block_size || offset < 0) {
			num_errors++; bad_index = 1;
			sprintf(message, "Bad block index offset %"PRId64" between block %d and %d\n", offset, i-1, i);
			fprintf(stdout, "%s", message);
			if (logfile) fprintf(lfp, "%s", message);
		}
		dt = (si8)(indx_array[i].time - indx_array[i-1].time);
		if (dt < 0) {
			num_errors++; bad_index = 1;
			sprintf(message, "Bad block timestamps: %"PRIu64" in block %d and %"PRIu64" in block %d (diff %"PRId64")\n", indx_array[i-1].time, i-1, indx_array[i].time, i, dt);
			fprintf(stdout, "%s", message);
			if (logfile) fprintf(lfp, "%s", message);
		}
		ds = (si8)(indx_array[i].sample_number - indx_array[i-1].sample_number);
		if (ds > header.maximum_block_length || ds < 0) {
			num_errors++; bad_index = 1;
			sprintf(message, "Bad block sample numbers: %"PRIu64" in block %d and %"PRIu64" in block %d\n", indx_array[i-1].sample_number, i-1, indx_array[i].sample_number, i);
			fprintf(stdout, "%s", message);
			if (logfile) fprintf(lfp, "%s", message);
		}
	}	

	if (bad_index) return(num_errors);
	
	data_end = indx_array[0].file_offset;
	
	//Loop through data blocks
	for (i=0; i<header.number_of_index_entries; i++) {
		if(indx_array[i].file_offset == data_end) { //read data
			if (i + blocks_per_read >= header.number_of_index_entries) {
				blocks_per_read = header.number_of_index_entries - i;
				data_end = header.index_data_offset;
			}
			else {
				data_end = indx_array[blocks_per_read + i].file_offset;
			}
			
			data_start = indx_array[i].file_offset;
			fseek(mfp, indx_array[i].file_offset, SEEK_SET);
			n = fread(data, 1, data_end - indx_array[i].file_offset, mfp);
			if (n != data_end - indx_array[i].file_offset || ferror(mfp)) {
				fprintf(stderr, "[%s] Error reading mef data %s\n", __FUNCTION__, mef_filename); 
				fclose(mfp); fclose(lfp);
				return(1); 
			}
		}
		offset = indx_array[i].file_offset - data_start;
		n = read_RED_block_header(data + offset, &bk_hdr);
		
		//check that the block length agrees with index array to within 8 bytes
		//(differences less than 8 bytes caused by padding to maintain boundary alignment)
		if (i <  header.number_of_index_entries-1)
			block_size = indx_array[i+1].file_offset - indx_array[i].file_offset;
		else 
			block_size = header.index_data_offset - indx_array[i].file_offset;
		
		if ( abs(block_size - (bk_hdr.compressed_bytes + BLOCK_HEADER_BYTES)) > 8 )
		{
			num_errors++;
			sprintf(message, "%s: Block %d size %u disagrees with index array offset %u\n", mef_filename, i, 
				(bk_hdr.compressed_bytes + BLOCK_HEADER_BYTES), block_size);
			fprintf(stdout, "%s", message);
			if (logfile) fprintf(lfp, "%s", message);
		}
		else //DON'T check CRC if block size is wrong- will crash the program
		{
			crc = calculate_compressed_block_CRC(data + offset);
			
			if (crc != bk_hdr.CRC_32) {
				num_errors++;
				sprintf(message, "%s: CRC error in block %d\n", mef_filename, i);
				fprintf(stdout, "%s", message);
				fprintf(stdout, "samples %d time %"PRIu64" diff_count %d max %d min %d discontinuity %d\n", bk_hdr.sample_count, 
					bk_hdr.block_start_time, bk_hdr.difference_count, bk_hdr.max_value, bk_hdr.min_value, 
					bk_hdr.discontinuity);
				if (logfile) {
					fprintf(lfp, "%s", message);
					fprintf(lfp, "samples %d time %"PRIu64" diff_count %d max %d min %d discontinuity %d\n", bk_hdr.sample_count, 
						bk_hdr.block_start_time, bk_hdr.difference_count, bk_hdr.max_value, bk_hdr.min_value, 
						bk_hdr.discontinuity);
				}
			}
		}
		//check data block boundary alignment in file
		if (indx_array[i].file_offset % 8) {
			num_errors++;
			sprintf(message, "%s: Block %d is not 8-byte boundary aligned \n", mef_filename, i);
			fprintf(stdout, "%s", message);
			if (logfile) fprintf(lfp, "%s", message);
		}
		if (bk_hdr.block_start_time < header.recording_start_time) {
			num_errors++;
			sprintf(message, "%s: Block %d start time %"PRIu64" is earlier than recording start time\n", mef_filename, i, bk_hdr.block_start_time);
			fprintf(stdout, "%s", message);
			if (logfile) fprintf(lfp, "%s", message);
		}
		if (bk_hdr.block_start_time > header.recording_end_time) {
			num_errors++;
			sprintf(message, "%s: Block %d start time %"PRIu64" is later than recording end time\n", mef_filename, i, bk_hdr.block_start_time);
			fprintf(stdout, "%s", message);
			if (logfile) fprintf(lfp, "%s", message);
		}
	}

	now = time(NULL);
	sprintf(message, "File %s check of %"PRIu64" data blocks completed with %"PRIu64" errors found.\n\n", mef_filename, header.number_of_index_entries, num_errors);
	fprintf(stdout, "%s", message);
	if (logfile) fprintf(lfp, "%s", message);

	free(indx_array); indx_array = NULL;
	free(data); data = NULL;
	
	fclose(mfp);
	if (logfile) fclose(lfp);
	
	return(num_errors);
}

ui4 update_crc_32(ui4 crc, si1 c ) {
	//extern ui4 crc_tab32[256];
	//void init_crc32_tab();
    ui4 tmp, long_c;
	
    long_c = 0x000000ff & (ui4) c;
	
    //if ( ! crc_tab32_init ) init_crc32_tab();
	
    tmp = crc ^ long_c;
    crc = (crc >> 8) ^ crc_tab32[ tmp & 0xff ];
	
    return crc;
	
}  /* update_crc_32 */


static inline void dec_normalize(ui4 *range, ui4 *low_bound, ui1 *in_byte, ui1 **ib_p)
{
	ui4 low, rng;
	ui1 in, *ib;
	
	low = *low_bound; 
	in = *in_byte;
	rng = *range;
	ib = *ib_p;
	
	while (rng <= BOTTOM_VALUE)
	{   low = (low << 8) | ((in << EXTRA_BITS) & 0xff);
		in = *ib++;
		low |= in >> (8 - EXTRA_BITS);
		rng <<= 8;
	}
	*low_bound = low; 
	*in_byte = in;
	*range = rng;
	*ib_p = ib;
	
	return;
}


ui8 RED_decompress_block(ui1 *in_buffer, si4 *out_buffer, si1 *diff_buffer, si1 *key, ui1 validate_CRC, ui1 data_encryption, RED_BLOCK_HDR_INFO *block_hdr_struct)
{
	ui4	cc, cnts[256], cum_cnts[257], block_len, comp_block_len, checksum;
	ui4	symbol, scaled_tot_cnts, tmp, range_per_cnt, diff_cnts, checksum_read;
	ui1	*ui1_p;
	si1	*si1_p1, *si1_p2, *db_p, discontinuity;
	si4	i, current_val, *ob_p, max_data_value, min_data_value;
	ui8 time_value;
	void AES_decryptWithKey(), AES_decrypt();
	ui4	low_bound;
	ui4	range;
	ui1	in_byte;
	ui1	*ib_p;
	
	/*** parse block header ***/
	ib_p = in_buffer;
	checksum_read = *(ui4 *)ib_p; ib_p += 4;
	comp_block_len = *(ui4 *)ib_p; ib_p += 4;
	time_value = *(ui8 *)ib_p; ib_p += 8;
	diff_cnts = *(ui4 *)ib_p; ib_p += 4;
	block_len = *(ui4 *)ib_p; ib_p += 4;
	
	max_data_value = 0; min_data_value = 0;
	ui1_p = (ui1 *) &max_data_value; 
	for (i = 0; i < 3; ++i) { *ui1_p++ = *ib_p++; }	
	*ui1_p++ = (*(si1 *)(ib_p-1)<0) ? -1 : 0; //sign extend
	ui1_p = (ui1 *) &min_data_value; 
	for (i = 0; i < 3; ++i) { *ui1_p++ = *ib_p++; }	
	*ui1_p++ = (*(si1 *)(ib_p-1)<0) ? -1 : 0; //sign extend
	
	discontinuity = *ib_p++;
	
	if (validate_CRC==MEF_TRUE && block_hdr_struct != NULL) {
		//calculate CRC checksum to validate- skip first 4 bytes
		checksum = 0xffffffff;
		for (i = 4; i < comp_block_len + BLOCK_HEADER_BYTES; i++)
			checksum = update_crc_32(checksum, *(out_buffer+i));
		
		if (checksum != checksum_read) block_hdr_struct->CRC_validated = 0;
		else block_hdr_struct->CRC_validated = 1;
	}
	
	if (data_encryption==MEF_TRUE)
		if (key==NULL) {
			fprintf(stderr, "[%s] Error: Null Encryption Key with encrypted block header\n", __FUNCTION__);
			return(-1);
		}
		else
			AES_decryptWithKey(ib_p, ib_p, key); //pass in expanded key
	
	for (i = 0; i < 256; ++i) { cnts[i] = (ui4) *ib_p++; }
	
	if (block_hdr_struct != NULL) {	
		block_hdr_struct->CRC_32 = checksum_read;
		block_hdr_struct->block_start_time = time_value;
		block_hdr_struct->compressed_bytes = comp_block_len;
		block_hdr_struct->difference_count = diff_cnts;
		block_hdr_struct->sample_count = block_len;
		block_hdr_struct->max_value = max_data_value;
		block_hdr_struct->min_value = min_data_value;
		block_hdr_struct->discontinuity = discontinuity;
	}
	
	/*** generate statistics ***/
	cum_cnts[0] = 0;
	for (i = 0; i < 256; ++i)
		cum_cnts[i + 1] = cnts[i] + cum_cnts[i];
	scaled_tot_cnts = cum_cnts[256];
	
	
	/*** range decode ***/
	diff_buffer[0] = -128; db_p = diff_buffer + 1;	++diff_cnts;	// initial -128 not coded in encode (low frequency symbol)
	ib_p = in_buffer + BLOCK_HEADER_BYTES + 1;	// skip initial dummy byte from encode
	in_byte = *ib_p++;
	low_bound = in_byte >> (8 - EXTRA_BITS);
	range = (ui4) 1 << EXTRA_BITS;
	for (i = diff_cnts; i--;) {
		dec_normalize(&range, &low_bound, &in_byte, &ib_p);
		
		tmp = low_bound / (range_per_cnt = range / scaled_tot_cnts);			
		cc = (tmp >= scaled_tot_cnts ? (scaled_tot_cnts - 1) : tmp);
		if (cc > cum_cnts[128]) {
			for (symbol = 255; cum_cnts[symbol] > cc; symbol--);
		} else {
			for (symbol = 1; cum_cnts[symbol] <= cc; symbol++);
			--symbol;
		}
		low_bound -= (tmp = range_per_cnt * cum_cnts[symbol]);
		if (symbol < 255)
			range = range_per_cnt * cnts[symbol];
		else
			range -= tmp;
		*db_p++ = symbol;
	}
	dec_normalize(&range, &low_bound, &in_byte, &ib_p);
	
	/*** generate output data from differences ***/
	si1_p1 = (si1 *) diff_buffer;
	ob_p = out_buffer;
	for (current_val = 0, i = block_len; i--;) {
		if (*si1_p1 == -128) {					// assumes little endian input
			si1_p2 = (si1 *) &current_val;
			*si1_p2++ = *++si1_p1; *si1_p2++ = *++si1_p1; *si1_p2++ = *++si1_p1;
			*si1_p2 = (*si1_p1++ < 0) ? -1 : 0;
		} else
			current_val += (si4) *si1_p1++;
		*ob_p++ = current_val;
	}
	return(comp_block_len + BLOCK_HEADER_BYTES);
}



inline void enc_normalize(RANGE_STATS *rstats)
{
	while (rstats->range <= BOTTOM_VALUE) {
		if (rstats->low_bound < (ui4 ) CARRY_CHECK) {		// no carry possible => output
			*(rstats->ob_p++) = rstats->out_byte;
			for(; rstats->underflow_bytes; rstats->underflow_bytes--)
				*(rstats->ob_p++) = 0xff;
			rstats->out_byte = (ui1) (rstats->low_bound >> SHIFT_BITS);
		} else if (rstats->low_bound & TOP_VALUE) {		// carry now, no future carry
			*(rstats->ob_p++) = rstats->out_byte + 1;
			for(; rstats->underflow_bytes; rstats->underflow_bytes--)
				*(rstats->ob_p++) = 0;
			rstats->out_byte = (ui1) (rstats->low_bound >> SHIFT_BITS);
		} else						// pass on a potential carry
			rstats->underflow_bytes++;
		rstats->range <<= 8;
		rstats->low_bound = (rstats->low_bound << 8) & TOP_VALUE_M_1;
	}
	
	return;
}


inline void encode_symbol(ui1 symbol, ui4 symbol_cnts, ui4 cnts_lt_symbol, ui4 tot_cnts, RANGE_STATS *rstats )
{
	ui4	r, tmp;
	
	enc_normalize(rstats);
	rstats->low_bound += (tmp = (r = rstats->range / tot_cnts) * cnts_lt_symbol);
	if (symbol < 0xff)			// not last symbol
		rstats->range = r * symbol_cnts;
	else						// last symbol
		rstats->range -= tmp;	// special case improves compression
	// at expense of speed
	return;
}


void done_encoding(RANGE_STATS *rstats)
{
	ui4	tmp;
	
	enc_normalize(rstats);
	
	tmp = rstats->low_bound;
	tmp = (tmp >> SHIFT_BITS) + 1;
	if (tmp > 0xff) {
		*(rstats->ob_p++) = rstats->out_byte + 1;
		for(; rstats->underflow_bytes; rstats->underflow_bytes--)
			*(rstats->ob_p++) = 0;
	} else {
		*(rstats->ob_p++) = rstats->out_byte;
		for(; rstats->underflow_bytes; rstats->underflow_bytes--)
			*(rstats->ob_p++) = 0xff;
	}
	*(rstats->ob_p++) = tmp & 0xff; *(rstats->ob_p++) = 0; *(rstats->ob_p++) = 0; *(rstats->ob_p++) = 0;
	
	return;
}


ui8 RED_compress_block(si4 *in_buffer, ui1 *out_buffer, ui4 num_entries, ui8 uUTC_time, ui1 discontinuity,
					   si1 *key, ui1 data_encryption, RED_BLOCK_HDR_INFO *block_hdr)
{
	ui4	cum_cnts[256], cnts[256], max_cnt, scaled_tot_cnts, extra_bytes;
	ui4	diff_cnts, comp_block_len, comp_len, encrypted_segments, checksum;
	ui1	diff_buffer[num_entries * 4], *ui1_p1, *ui1_p2, *ehbp;
	si1	*si1_p1, *si1_p2;
	si4	i, diff, *ib_p, pad_bytes, max_data_value, min_data_value;
	sf8	stats_scale, sum_abs_diff, temp_sf8;
	RANGE_STATS rng_st;
	void AES_encryptWithKey();
	
		
	/*** generate differences ***/
	si1_p1 = (si1 *) diff_buffer;
	si1_p2 = (si1 *) in_buffer;
	*si1_p1++ = *si1_p2++;
	*si1_p1++ = *si1_p2++;
	*si1_p1++ = *si1_p2;	// first entry is full value (3 bytes)
	
	max_data_value = min_data_value = in_buffer[0];
	
	for (i = 1; i < num_entries; i++) {
		diff = in_buffer[i] - in_buffer[i - 1];
		if (in_buffer[i] > max_data_value) max_data_value = in_buffer[i];
		else if (in_buffer[i] < min_data_value) min_data_value = in_buffer[i];
		if (diff > 127 || diff < -127) {				// for little endian input
			si1_p2 = (si1 *) (in_buffer + i);
			*si1_p1++ = -128;
			*si1_p1++ = *si1_p2++;
			*si1_p1++ = *si1_p2++;
			*si1_p1++ = *si1_p2;
		} else
			*si1_p1++ = (si1) diff;
	}
	diff_cnts = (si4) (si1_p1 - (si1 *) diff_buffer);
	
	/*** generate statistics ***/
	memset((void *)cnts, 0, 1024);
	ui1_p1 = diff_buffer;
	for (i = diff_cnts; i--;)
		++cnts[*ui1_p1++];
	
	max_cnt = 0;
	for (i = 0; i < 256; ++i)
		if (cnts[i] > max_cnt)
			max_cnt = cnts[i];
	if (max_cnt > 255) {
		stats_scale = (sf8) 254.999 / (sf8) max_cnt;
		for (i = 0; i < 256; ++i)
			cnts[i] = (ui4) ceil((sf8) cnts[i] * stats_scale);
	}
	cum_cnts[0] = 0;
	for (i = 0; i < 255; ++i)
		cum_cnts[i + 1] = cnts[i] + cum_cnts[i];
	scaled_tot_cnts = cnts[255] + cum_cnts[255];
	
	
	/*** range encode ***/
	rng_st.low_bound = rng_st.out_byte = rng_st.underflow_bytes = 0;
	rng_st.range = TOP_VALUE;
	rng_st.ob_p = out_buffer + BLOCK_HEADER_BYTES; //NOTE: ob_p is declared GLOBAL
	ui1_p1 = diff_buffer;
	for(i = diff_cnts; i--; ++ui1_p1)
		encode_symbol(*ui1_p1, cnts[*ui1_p1], cum_cnts[*ui1_p1], scaled_tot_cnts, &rng_st);
	done_encoding(&rng_st);
	
	
	//ensure 8-byte alignment for next block
	comp_len = (ui4)(rng_st.ob_p - out_buffer);
	extra_bytes = 8 - comp_len % 8;
	
	if (extra_bytes < 8) {
		for (i=0; i<extra_bytes; i++)
			*(rng_st.ob_p++) = FILLER_BYTE; 
	}
	
	/*** write the packet & packet header ***/
	/* 4 byte checksum, 8 byte time value, 4 byte compressed byte count, 4 byte difference count,  */
	/* 4 byte sample count, 3 byte data maximum, 3 byte data minimum, 256 byte model counts */
	
	ui1_p1 = out_buffer;
	
	//fill checksum with zero as a placeholder
	*(ui4 *)(ui1_p1) = 0; ui1_p1 += 4;
	
	comp_block_len = (ui4)((rng_st.ob_p - out_buffer) - BLOCK_HEADER_BYTES);
	if (block_hdr != NULL) block_hdr->compressed_bytes = comp_block_len;
	*(ui4 *)(ui1_p1) = comp_block_len; ui1_p1 += 4;
	
	if (block_hdr != NULL) block_hdr->block_start_time = uUTC_time;
	*(ui8 *)(ui1_p1) = uUTC_time; ui1_p1 += 8;
	
	if (block_hdr != NULL) block_hdr->difference_count = diff_cnts;
	*(ui4 *)(ui1_p1) = diff_cnts; ui1_p1 += 4;
	
	if (block_hdr != NULL) block_hdr->sample_count = num_entries;
	*(ui4 *)(ui1_p1) = num_entries; ui1_p1 += 4;
	
	if (block_hdr != NULL) block_hdr->max_value = max_data_value;
	ui1_p2 = (ui1 *) &max_data_value; //encode max and min values as si3
	for (i = 0; i < 3; ++i)
		*ui1_p1++ = *ui1_p2++;
	
	if (block_hdr != NULL) block_hdr->min_value = min_data_value;
	ui1_p2 = (ui1 *) &min_data_value; //encode max and min values as si3
	for (i = 0; i < 3; ++i) 
		*ui1_p1++ = *ui1_p2++;
	
	if (block_hdr != NULL) block_hdr->discontinuity = discontinuity; 
	*ui1_p1++ = discontinuity;
	
	ehbp = ui1_p1;
	
	for (i = 0; i < 256; ++i)
		*ui1_p1++ = (ui1) cnts[i];
	
	if (data_encryption==MEF_TRUE) {
		if (key==NULL) {
			fprintf(stderr, "[%s] Error: Null Encryption Key with encrypted block header\n", __FUNCTION__);
			return(-1);
		}
		else
			AES_encryptWithKey(ehbp, ehbp, key); //expanded key
	}

		
	//calculate CRC checksum and save in block header- skip first 4 bytes
	checksum = 0xffffffff;
	for (i = 4; i < comp_block_len + BLOCK_HEADER_BYTES; i++)
		checksum = update_crc_32(checksum, *(out_buffer+i));
	
	if (block_hdr != NULL) block_hdr->CRC_32 = checksum;
	ui1_p1 = out_buffer;
	ui1_p2 = (ui1 *) &checksum;
	for (i = 0; i < 4; ++i)
		*ui1_p1++ = *ui1_p2++;
	
	return(comp_block_len + BLOCK_HEADER_BYTES);
}

/* get cpu endianness: 0 = big, 1 = little */
ui1	cpu_endianness()
{
	ui2	x = 1;
	
	return(*((ui1 *) &x));
}

/* in place */
void	reverse_in_place(void *x, si4 len)
{
	ui1	*pf, *pb, t;
	si4	i;
	
	pf = (ui1 *) x;
	pb = pf + len;
	for (i = len >> 1; i--;) {
		t = *pf;
		*pf++ = *--pb;
		*pb = t;
	}
}

/* value returning functions */
si2	rev_si2(si2 x)
{
	ui1	*pf, *pb;
	si2	xr;
	
	pf = (ui1 *) &x;
	pb = (ui1 *) &xr + 1;
	
	*pb-- = *pf++;
	*pb = *pf;
	
	return(xr);
}

ui2	rev_ui2(ui2 x)
{
	ui1	*pf, *pb;
	ui2	xr;
	
	pf = (ui1 *) &x;
	pb = (ui1 *) &xr + 1;
	
	*pb-- = *pf++;
	*pb = *pf;
	
	return(xr);
}

si4	rev_si4(si4 x)
{
	ui1	*pf, *pb;
	si4	xr;
	
	pf = (ui1 *) &x;
	pb = (ui1 *) &xr + 3;
	
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb = *pf;
	
	return(xr);
}

ui4	rev_ui4(ui4 x)
{
	ui1	*pf, *pb;
	ui4	xr;
	
	pf = (ui1 *) &x;
	pb = (ui1 *) &xr + 3;
	
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb = *pf;
	
	return(xr);
}

sf4	rev_sf4(sf4 x)
{
	ui1	*pf, *pb;
	sf4	xr;
	
	pf = (ui1 *) &x;
	pb = (ui1 *) &xr + 3;
	
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb = *pf;
	
	return(xr);
}

si8	rev_si8(si8 x)
{
	ui1	*pf, *pb;
	si8	xr;
	
	pf = (ui1 *) &x;
	pb = (ui1 *) &xr + 7;
	
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb = *pf;
	
	return(xr);
	
}

ui8	rev_ui8(ui8 x)
{
	ui1	*pf, *pb;
	ui8	xr;
	
	if (x)
	{
		pf = (ui1 *) &x;
		pb = (ui1 *) &xr + 7;
		
		*pb-- = *pf++;
		*pb-- = *pf++;
		*pb-- = *pf++;
		*pb-- = *pf++;
		*pb-- = *pf++;
		*pb-- = *pf++;
		*pb-- = *pf++;
		*pb = *pf; 
		
		return(xr);
	}
	else
	{
		return(x);
	}
}

sf8	rev_sf8(sf8 x)
{
	ui1	*pf, *pb;
	sf8	xr;
	
	pf = (ui1 *) &x;
	pb = (ui1 *) &xr + 7;
	
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb-- = *pf++;
	*pb = *pf;
	
	return(xr);
}

