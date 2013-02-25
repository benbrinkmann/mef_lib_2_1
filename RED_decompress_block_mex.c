//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "/Applications/MATLAB_R2010b.app/extern/include/mex.h"
#include "mef.h"


#define BIG_ENDIAN_CODE		0
#define LITTLE_ENDIAN_CODE	1

/*
void decomp_mef2(char *f_name, unsigned long long int start_idx, unsigned long long int end_idx, int *decomp_data, char *password)
{
	char			*c, *comp_data, *cdp, *last_block_p, encryptionKey[240];
	unsigned char		*header, *diff_buffer;
	int			*dcdp, *temp_data_buf;
	unsigned int		cpu_endianness, n_read, comp_data_len, bytes_decoded, tot_samples;
	unsigned int		i, n_index_entries, tot_index_fields, kept_samples, skipped_samples;
	unsigned long long int	start_block_file_offset, end_block_file_offset, start_block_idx, end_block_idx;
	unsigned long long int	*index_data, last_block_len, RED_decompress_block();
	FILE			*fp;
	MEF_HEADER_INFO		hdr_info;
	RED_BLOCK_HDR_INFO	block_hdr;
	void AES_KeyExpansion();
		
	// get cpu endianness
	cpu_endianness = 1;
	c = (char *) &cpu_endianness;
	cpu_endianness = (unsigned int) *c;
	if (cpu_endianness != LITTLE_ENDIAN_CODE) {
		mexErrMsgTxt("[decomp_mef2] is currently only compatible with little-endian machines => exiting");
		return;
	}
	
	// read header
	fp = fopen(f_name, "r");
	if (fp == NULL) { 
		printf("[decomp_mef2] could not open the file \"%s\" => exiting\n",  f_name);
		return;
	}
	header = (unsigned char *) malloc(MEF_HEADER_LENGTH);  // malloc to ensure boundary alignment
	n_read = fread((void *) header, sizeof(char), (size_t) MEF_HEADER_LENGTH, fp);
	if (n_read != MEF_HEADER_LENGTH) {
		printf("[decomp_mef2] error reading the file \"%s\" => exiting\n",  f_name);
		return;
	}	
	if ((read_mef_header_block(header, &hdr_info, password))) {
		printf("[decomp_mef2] header read error for file \"%s\" => exiting\n", f_name);
		return;		
	}
	free(header);
	
	// get file endianness 
	if (hdr_info.byte_order_code != LITTLE_ENDIAN_CODE) {
		mexErrMsgTxt("[decomp_mef2] is currently only compatible with little-endian files (file \"%s\") => exiting");
		return;
	}

	if (hdr_info.data_encryption_used) {
		AES_KeyExpansion(4, 10, encryptionKey, hdr_info.session_password); 
	}
	else
		*encryptionKey = 0;
	
	// read in index data
	n_index_entries = (unsigned int) hdr_info.number_of_index_entries;
	fseeko(fp, (off_t) hdr_info.index_data_offset, SEEK_SET);
	tot_index_fields = n_index_entries * 3;	// 3 fields per entry
	index_data = (unsigned long long int *) malloc(tot_index_fields * sizeof(unsigned long long int));
	if (index_data == NULL) {
		printf("[decomp_mef2] could not allocate enough memory for file \"%s\" => exiting\n", f_name);
		return;
	}
	
	n_read = fread(index_data, sizeof(unsigned long long int), (size_t) tot_index_fields, fp);
	if (n_read != tot_index_fields) {
		printf("[decomp_mef2] error reading index data for file \"%s\" => exiting\n", f_name);
		return;
	}		

	// find block containing start of requested range
	if (start_idx >= hdr_info.number_of_samples) {
		printf("[decomp_mef2] start index for file \"%s\" exceeds the number of samples in the file => exiting\n", f_name);
		return;
	}
	for (i = 2; i < tot_index_fields; i += 3)
		if (index_data[i] > start_idx)
			break;
	i -= 3; // rewind one triplet
	start_block_idx = index_data[i]; // sample index of start of block containing start index
	start_block_file_offset = index_data[i - 1];  // file offset of block containing start index
	
	// find block containing end of requested range 
	if (end_idx >= hdr_info.number_of_samples) {
		printf("[decomp_mef2] end index for file \"%s\" exceeds the number of samples in the file => tail values will be zeros\n", f_name);
		end_idx = hdr_info.number_of_samples - 1;
	}
	for (; i < tot_index_fields; i += 3)
		if (index_data[i] > end_idx)
			break;
	i -= 3; // rewind one triplet
	end_block_idx = index_data[i]; // sample index of start of block containing end index
	end_block_file_offset = index_data[i - 1];  // file offset of block containing end index
	
	if (i == (tot_index_fields - 1))
		last_block_len = hdr_info.index_data_offset - end_block_file_offset;  // file offset of index data
	else
		last_block_len = index_data[i + 2] - end_block_file_offset;  // file offset of next block
	free(index_data);
	
	// allocate input buffer 
	comp_data_len = (unsigned int) (end_block_file_offset - start_block_file_offset + last_block_len);
	comp_data = (char *) malloc(comp_data_len); 
	if (comp_data == NULL) {
		printf("[decomp_mef2] could not allocate enough memory for file \"%s\" => exiting\n", f_name);
		return;
	}
	
	// read in compressed data 
	fseeko(fp, (off_t) start_block_file_offset, SEEK_SET);
	n_read = fread(comp_data, sizeof(char), (size_t) comp_data_len, fp);
	if (n_read != comp_data_len) {
		printf("[decomp_mef2] error reading data for file \"%s\" => exiting\n", f_name);
		return;
	}
	fclose(fp);
		
	// decompress data
	
	// decode first block to temp array
	cdp = comp_data;  
	diff_buffer = (unsigned char *) malloc(hdr_info.maximum_block_length * 4);
	temp_data_buf = (int *) malloc(hdr_info.maximum_block_length * 4);
	bytes_decoded = (unsigned int) RED_decompress_block(cdp, temp_data_buf, diff_buffer, encryptionKey, 0, &block_hdr);
	cdp += bytes_decoded;
	
	// copy requested samples from first block to output buffer
	skipped_samples = (unsigned int) (start_idx - start_block_idx);
	kept_samples = block_hdr.sample_count - skipped_samples;
	tot_samples = (unsigned int) (end_idx - start_idx + 1);
	if (kept_samples >= tot_samples) { // start and end indices in same block => already done
		memcpy((void *) decomp_data, (void *) (temp_data_buf + skipped_samples), tot_samples * sizeof(int));
		free(comp_data);
		return;
	}
	memcpy((void *) decomp_data, (void *) (temp_data_buf + skipped_samples), kept_samples * sizeof(int));
	dcdp = decomp_data + kept_samples;
	
	last_block_p = comp_data + (unsigned int) (end_block_file_offset - start_block_file_offset);
	while (cdp < last_block_p) {
		bytes_decoded = (unsigned int) RED_decompress_block(cdp, dcdp, diff_buffer, encryptionKey, 0, &block_hdr);
		cdp += bytes_decoded;
		dcdp += block_hdr.sample_count; 
	}
	
	// decode last block to temp array
	(void) RED_decompress_block(cdp, temp_data_buf, diff_buffer, encryptionKey, 0, &block_hdr);

	// copy requested samples from last block to output buffer
	kept_samples = (unsigned int) (end_idx - end_block_idx + 1);
	memcpy((void *) dcdp, (void *) temp_data_buf, kept_samples * sizeof(int));
	
	free(comp_data);
	free(diff_buffer);
	free(temp_data_buf);

	return;
}
*/

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

void RED_decompress_block_mex(ui1 *in_buffer, si4 *out_buffer, si1 *diff_buffer, si1 *key, ui1 validate_CRC, ui1 data_encryption, RED_BLOCK_HDR_INFO *block_hdr_struct)
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
	
	/*if (validate_CRC==MEF_TRUE && block_hdr_struct != NULL) {
		//calculate CRC checksum to validate- skip first 4 bytes
		checksum = 0xffffffff;
		for (i = 4; i < comp_block_len + BLOCK_HEADER_BYTES; i++)
			checksum = update_crc_32(checksum, *(out_buffer+i));
            
		if (checksum != checksum_read) block_hdr_struct->CRC_validated = 0;
		else block_hdr_struct->CRC_validated = 1;
	}*/
	
	/*if (data_encryption==MEF_TRUE)
		if (key==NULL) {
			fprintf(stderr, "[%s] Error: Null Encryption Key with encrypted block header\n", __FUNCTION__);
			//return(-1);
            return;
		}
		else
			AES_decryptWithKey(ib_p, ib_p, key); //pass in expanded key
     */
	
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
	//return(comp_block_len + BLOCK_HEADER_BYTES);
    return;
}

/*
// The mex gateway routine 
void mexFunction(int nlhs, mxArray *plhs[], int nrhs, const mxArray *prhs[])
{
	char			*f_name, *password;
	int			buf_len, status, decomp_data_len, dims[2], *decomp_data;
	unsigned long long int	start_idx, end_idx, long_decomp_data_len;
	void			decomp_mef2();
	
	//  Check for proper number of arguments 
	if (nrhs != 4) 
		mexErrMsgTxt("[decomp_mef2] four inputs required: file_name, start_index, stop_index, password");
	if (nlhs != 1) 
		mexErrMsgTxt("[decomp_mef2] one output required: decompressed_array");
	
	// get the input file name (argument 1)
	if (mxIsChar(prhs[0]) != 1) { // Check to make sure the first input argument is a string 
		mexErrMsgTxt("[decomp_mef2] file name must be a string => exiting");
		return;
	}	
	buf_len = (mxGetM(prhs[0]) * mxGetN(prhs[0])) + 2; // Get the length of the input string 
	f_name = malloc(buf_len); // Allocate memory for file_name string
	status = mxGetString(prhs[0], f_name, buf_len);
	if (status != 0) {
		mexWarnMsgTxt("[decomp_mef2] not enough space for input file name string => exiting");
		return;
	}
	
	//  get the start index (argument 2)
	if (!mxIsDouble(prhs[1]) || mxIsComplex(prhs[1]) || (mxGetN(prhs[1]) * mxGetM(prhs[1]) != 1) ) { // Check to make sure the second input argument is a scalar
		mexErrMsgTxt("[decomp_mef2] start index must be a scalar => exiting");
		return;
	}	
	start_idx = (unsigned long long int) mxGetScalar(prhs[1]);
	if (start_idx > 0.0)
		start_idx -= 1.0;     // convert to C indexing
	
	//  get the end index (argument 3)
	if (!mxIsDouble(prhs[2]) || mxIsComplex(prhs[2]) || (mxGetN(prhs[2]) * mxGetM(prhs[2]) != 1) ) { // Check to make sure the third input argument is a scalar
		mexErrMsgTxt("[decomp_mef2] end index must be a scalar => exiting");
		return;
	}	
	end_idx = (unsigned long long int) mxGetScalar(prhs[2]);
	end_idx -= 1.0;     // convert to C indexing
	
	// check that indices are in proper order
	if (end_idx < start_idx) {
		mexErrMsgTxt("[decomp_mef2] end index exceeds start index => exiting");
		return;
	}

	// get the password (argument 4)
	if (mxIsChar(prhs[3]) != 1) { // Check to make sure the fourth input argument is a string 
		mexErrMsgTxt("[decomp_mef2] Password must be a string => exiting");
		return;
	}	
	buf_len = (mxGetM(prhs[3]) * mxGetN(prhs[3])) + 2; // Get the length of the input string 
	password = malloc(buf_len); // Allocate memory for file_name string
	status = mxGetString(prhs[3], password, buf_len);
	if (status != 0) {
		mexWarnMsgTxt("[decomp_mef2] not enough space for password string => exiting");
		return;
	}

	// Set the output pointer to the output matrix. 
	long_decomp_data_len = end_idx - start_idx + (unsigned long long int) 1;
	if (long_decomp_data_len >= (unsigned long long int) (1 << 31)) {
		mexErrMsgTxt("[decomp_mef2] requested memory exceeds Matlab limit => exiting");
		return;
	}
	decomp_data_len = (int) long_decomp_data_len;
	dims[0] = decomp_data_len; dims[1] = 1;
	plhs[0] = mxCreateNumericArray(2, dims, mxINT32_CLASS, mxREAL);
	
	// Create a C pointer to a copy of the output matrix. 
	decomp_data = (int *) mxGetPr(plhs[0]);
	if (decomp_data == NULL) {
		mexErrMsgTxt("[decomp_mef2] could not allocate enough memory => exiting");
		return;
	}
	
	// Call the C subroutine. 
	decomp_mef2(f_name, start_idx, end_idx, decomp_data, password);
	
	return;
} 
 */

// The mex gateway routine 
void mexFunction(int nlhs, mxArray *plhs[], int nrhs, const mxArray *prhs[])
{
	char			*f_name, *password;
	int			buf_len, status, decomp_data_len, dims[2], *decomp_data;
	unsigned long long int	start_idx, end_idx, long_decomp_data_len;
	void			RED_decompress_block_mex(ui1 *in_buffer, si4 *out_buffer, si1 *diff_buffer, si1 *key, ui1 validate_CRC, ui1 data_encryption, RED_BLOCK_HDR_INFO *block_hdr_struct);
	ui1 *in_buffer;
	si4 *out_buffer;
	si1 *diff_buffer;
	ui4 number_of_samples;
	char errortext[300];
	
	//  Check for proper number of arguments 
	if (nrhs != 1) 
		mexErrMsgTxt("[RED_decompress_block] one input required: in_buffer");
	if (nlhs != 1) 
		mexErrMsgTxt("[RED_decompress_block] one output required: out_buffer");
	
	// Create a C pointer to input matrix
	in_buffer = (ui1*) mxGetPr(prhs[0]);
	
	// determine number of samples from reading block header
	number_of_samples = *((ui4*)(in_buffer+RED_SAMPLE_COUNT_OFFSET));
	//sprintf(errortext,"number_of_samples = %u", number_of_samples);
	//mexErrMsgTxt(errortext);
	
	decomp_data_len = (int) number_of_samples;
	dims[0] = decomp_data_len; dims[1] = 1;
	plhs[0] = mxCreateNumericArray(2, dims, mxINT32_CLASS, mxREAL);
	
	// Create a C pointer to a copy of the output matrix. 
	out_buffer = (int *) mxGetPr(plhs[0]);
	if (out_buffer == NULL) {
		mexErrMsgTxt("[decomp_mef2] could not allocate enough memory => exiting");
		return;
	}
	
	// Call the C subroutine. 
	diff_buffer = (unsigned char *) malloc(number_of_samples * 4);
	RED_decompress_block_mex(in_buffer, out_buffer, diff_buffer, NULL, MEF_FALSE, MEF_FALSE, NULL);
	free(diff_buffer);
	
	return;
} 
