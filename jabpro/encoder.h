/**
 * libjabpro - Encoding/Decoding Library of Digital Seal (BSI TR-03137)
 *
 * Copyright 2022 by Fraunhofer SIT. All rights reserved.
 * See LICENSE file for full terms of use and distribution.
 *
 * Contact: Waldemar Berchtold, Huajian Liu <jabcode@sit.fraunhofer.de>
 *
 * @file encoder.h
 * @brief Encoder header
 */

#ifndef JABPRO_ENCODER_H
#define JABPRO_ENCODER_H

//for visa
#define SIGN_ALGO_VISA "brainpoolP224r1"
#define HASH_ALGO_VISA "SHA-224"
#define HASH_SIZE_VISA 224
#define SIGN_SIZE_VISA 448
//for address and place of residence sticker
#define SIGN_ALGO_STICKER "brainpoolP224r1"
#define HASH_ALGO_STICKER "SHA-224"
#define HASH_SIZE_STICKER 224
#define SIGN_SIZE_STICKER 448
//for other profiles
#define SIGN_ALGO "brainpoolP256r1"
#define HASH_ALGO "SHA-256"
#define HASH_SIZE 256
#define SIGN_SIZE 512

#define VALID_FROM 2016
#define VALID_FROM_VISA 2021
#define VALID_FROM_STICKER 2021
#define VALID_TIL 2025

/**
 * @brief Encoded profile header
*/
typedef struct {
	jpro_byte	magic_constant;
	jpro_byte	version;
	jpro_byte	country_id[2];
	jpro_int32	signer_cert_ref_length;
	jpro_byte*	signer_cert_ref;
	jpro_byte	document_issue_date[3];
	jpro_byte	signature_creation_date[3];
	jpro_byte	feature_ref;
	jpro_byte	document_type;
}jpro_header;

/**
 * @brief Encoded document feature
*/
typedef struct {
	jpro_byte	tag;	//an integer in the range 0-254
	jpro_byte	length;	//an integer in the range 0-254 denoting the length of the value
	jpro_byte*	value;	//a sequence of bytes
}jpro_feature;

/**
 * @brief Encoded profile
*/
typedef struct {
	jpro_header		header;
	jpro_int32		feature_cnt;	//the number of encoded features
	jpro_feature*	features;		//the encoded features
}jpro_profile;


extern jpro_feature_info create_feature_info ( jpro_char *name, jpro_int32 min_length, jpro_int32 max_length, jpro_boolean required, jpro_feature_type value_type );
extern jpro_profile_info *create_profile_info ( jpro_profile_type type, jpro_int32 feature_cnt, jpro_feature_info *features, jpro_crypto_info *crypto );
extern jpro_header_info create_header_info ( jpro_char* issuing_country, jpro_char* signer_country, jpro_char*	signer_id, jpro_char* certificate_ref, jpro_date issue_date, jpro_date signature_date );
extern jpro_crypto_info *create_crypto_info ( jpro_int32 hash_algo_cnt, jpro_crypto_algo* hash_algos, jpro_int32 signature_algo_cnt, jpro_crypto_algo*	signature_algos );
extern jpro_crypto_algo create_crypto_algo ( jpro_char* algo, jpro_int32 size, jpro_int32 valid_from, jpro_int32 valid_till );
extern void initialize_empty_feature_data( jpro_feature_info *feature );
extern jpro_boolean check_date ( jpro_date date );
extern jpro_crypto_info *get_crypto_info ( jpro_profile_type profile_type );
extern jpro_boolean check_length ( jpro_profile_info *profile_info );
extern jpro_boolean check_value_type( jpro_profile_info *profile_list );
extern jpro_boolean is_alphanum( jpro_char* s);
extern jpro_boolean is_numeric( jpro_char* s );
extern jpro_boolean is_utf_8( jpro_char* s );
extern jpro_header* encode_header( jpro_profile_info* profile_info );
extern jpro_byte* get_header_bytes( jpro_header* header, jpro_int32 length );
extern jpro_byte* date_encode( jpro_date date );
extern jpro_profile_info *get_sic_info();                           //social insurance card profile
extern jpro_data *get_encoded_sic( jpro_profile_info *profile_info );
extern jpro_crypto_info *get_crypto_sic();
extern jpro_profile_info *get_visa_info();                          //visa profile
extern jpro_data *get_encoded_visa( jpro_profile_info *profile_info );
extern jpro_crypto_info *get_crypto_visa();
extern jpro_profile_info *get_aad_info();                           //arrival attestation document profile
extern jpro_data *get_encoded_aad( jpro_profile_info *profile_info );
extern jpro_crypto_info *get_crypto_aad();
extern jpro_profile_info *get_rp_info();                            //residence permit profile
extern jpro_data *get_encoded_rp( jpro_profile_info *profile_info );
extern jpro_crypto_info *get_crypto_rp();
extern jpro_profile_info *get_addr_st_id_info();                    //address sticker profile for id card
extern jpro_data *get_encoded_addr_st_id( jpro_profile_info *profile_info );
extern jpro_crypto_info *get_crypto_addr_st_id();
extern jpro_profile_info *get_por_info();                           //place of residence sticker profile for passport
extern jpro_data *get_encoded_por( jpro_profile_info *profile_info );
extern jpro_crypto_info *get_crypto_por();
extern jpro_char* cat_strings( jpro_char* buffer, jpro_char* str1, jpro_char* str2, jpro_char* str3 );
extern jpro_data* get_length_tag( jpro_uint32 feature_length );
extern jpro_int32 check_header( jpro_header_info header );
extern jpro_profile_info *get_rp_supp_sheet_info();
extern jpro_data *get_encoded_rp_supp_sheet( jpro_profile_info *profile_info );
extern jpro_crypto_info *get_crypto_rp_supp_sheet();

extern void error_handler ( jpro_char* error_message, jpro_error_code error_code );



#endif
