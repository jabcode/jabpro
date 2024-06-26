/**
 * libjabpro - Encoding/Decoding Library of Digital Seal (BSI TR-03137)
 *
 * Copyright 2022 by Fraunhofer SIT. All rights reserved.
 * See LICENSE file for full terms of use and distribution.
 *
 * Contact: Waldemar Berchtold, Huajian Liu <jabcode@sit.fraunhofer.de>
 *
 * @file jabpro.h
 * @brief Main libjabpro header
 */

#ifndef JABPRO_H
#define JABPRO_H

#define VERSION "1.0.0"
#define BUILD_DATE __DATE__

typedef unsigned char 		jpro_byte;
typedef char 				jpro_char;
typedef unsigned char 		jpro_boolean;
typedef int 				jpro_int32;
typedef unsigned int 		jpro_uint32;
typedef short 				jpro_int16;
typedef unsigned short 		jpro_uint16;
typedef long long 			jpro_int64;
typedef unsigned long long	jpro_uint64;
typedef float				jpro_float;
typedef double              jpro_double;

/**
 * @brief Supported profiles
*/
typedef enum {
	JPRO_VISA,
	JPRO_ARRIVAL_ATTESTATION_DOCUMENT,
	JPRO_SOCIAL_INSURANCE_CARD,
	JPRO_RESIDENCE_PERMIT,
	JPRO_SUPPLEMENTARY_SHEET,
	JPRO_ADDRESS_STICKER_FOR_ID_CARD,
	JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT
}jpro_profile_type;

/**
 * @brief Document feature types
*/
typedef enum {
	JPRO_ALPHANUMERIC,
	JPRO_NUMERIC,
	JPRO_INTEGER,
	JPRO_DATE,
	JPRO_BINARY,
	JPRO_BINARY_UTF8
}jpro_feature_type;

/**
 * @brief Error codes
*/
typedef enum {
	OUT_OF_MEMORY,
	INVALID_VALUE_LENGTH,
	INVALID_VALUE_TYPE,
	UNSUPPORTED_PROFILE_TYPE,
	UNSUPPORTED_HEADER_VERSION,
	FEATURE_TAG_NOT_FOUND,
	SIGNATURE_TAG_NOT_FOUND,
	INVALID_DATE,
	WRONG_INPUT,
	UNKNOWN_PROFILE_TYPE,
	C40_VALUE_UNKNOWN,
	DATE_ENCODING_FAILED,
	SIGNATURE_NOT_FOUND,
	INVALID_HEADER,
	INVALID_LENGTH_TAG,
	INVALID_SIGNATURE_LENGTH,
	INVALID_FEATURE_COUNT,
	FEATURE_DATA_DOES_NOT_MATCH_PROFILE,
	REQUIRED_FEATURE_NOT_FOUND
}jpro_error_code;

/**
 * @brief Data structure
*/
typedef struct {
	jpro_int32	length;	//the length of data
	jpro_byte	data[];	//the binary data
}jpro_data;

/**
 * @brief Date structure
*/
typedef struct {
	jpro_char*	year;	//4-digit like "2022"
	jpro_char*	month;	//2-digit like "02"
	jpro_char*	day;	//2-digit like "09"
}jpro_date;

/**
 * @brief Header information
*/
typedef struct {
    jpro_char*  issuing_country;
	jpro_char*	signer_country;
	jpro_char*	signer_id;
	jpro_char*	certificate_ref;
	jpro_date	issue_date;			//document issue date
	jpro_date	signature_date;		//signature creation date
}jpro_header_info;

/**
 * @brief Document feature property and information
*/
typedef struct {
	jpro_char*			name;
	jpro_int32			min_length;		//the minimal length of bytes of the feature value
	jpro_int32			max_length;		//the maximal length of bytes of the feature value
	jpro_boolean 		required;		//True for required features, False for optional ones
	jpro_feature_type	value_type;		//the feature value type
	jpro_char*			value_string;	//variable for alphanumeric value, binary value or binary-utf8 value which must be encoded by UTF-8.
	jpro_date			value_date;		//variable for date value
	jpro_int32			value_int;		//variable for integer value
}jpro_feature_info;

/**
 * @brief Hash and signature algorithms
*/
typedef struct {
	jpro_char*	algo;
	jpro_int32	size;
	jpro_int32	valid_from; //year as an integer, which is included
	jpro_int32	valid_till;	//year as an integer, which is excluded
}jpro_crypto_algo;

/**
 * @brief Cryptograhpic informaiton for signing profiles (as defined in BSI TR-03116-2)
*/
typedef struct {
	jpro_int32			hash_algo_cnt;
	jpro_crypto_algo*	hash_algos;
	jpro_int32			signature_algo_cnt;
	jpro_crypto_algo*	signature_algos;	//expected algorithm name format e.g. ECDSA-brainpoolP384r1
}jpro_crypto_info;

/**
 * @brief Profile property and information
*/
typedef struct {
	jpro_profile_type	type;
	jpro_header_info 	header;
	jpro_int32			feature_cnt;	//the number of features
	jpro_feature_info*	features;
	jpro_crypto_info*	crypto;
}jpro_profile_info;

/**
 * @brief Profile list
*/
typedef struct {
	jpro_int32			profile_cnt;	//the number of profiles
	jpro_char**			profile_names;	//the profile names
	jpro_profile_type*	profile_types;	//the profile types
}jpro_profile_list;


extern jpro_profile_list* get_supported_profiles();
extern jpro_profile_info* get_profile_info(jpro_profile_type profile_type);
extern jpro_data* encode_profile(jpro_profile_info* profile_info);
extern jpro_data* append_signature(jpro_data* encoded_profile, jpro_data* signature);
extern jpro_header_info* decode_header(jpro_data* seal, jpro_profile_type* type);
extern jpro_int32 parse_seal(jpro_data* seal, jpro_data** encoded_profile, jpro_data** signature, jpro_int32 signature_length);
extern jpro_profile_info* decode_profile(jpro_data* encoded_profile);
extern jpro_char* get_last_error(jpro_uint32* error_code);
extern void free_profile_info( jpro_profile_info *profile_info );
extern void free_profile_list( jpro_profile_list* profile_list);
extern void free_header_info_data( jpro_header_info header );
extern void free_feature_values( jpro_profile_info *profile_info );

#endif
