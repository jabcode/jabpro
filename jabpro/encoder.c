/**
 * libjabpro - Encoding/Decoding Library of Digital Seal (BSI TR-03137)
 *
 * Copyright 2022 by Fraunhofer SIT. All rights reserved.
 * See LICENSE file for full terms of use and distribution.
 *
 * Contact: Waldemar Berchtold, Huajian Liu <jabcode@sit.fraunhofer.de>
 *
 * @file encoder.c
 * @brief Profile encoding
 */

#include "jabpro.h"
#include "encoder.h"
#include "c40.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

/**
 * @brief Global error code
*/
jpro_error_code global_error_code;
jpro_char jpro_error_msg[256];

/**
 * @brief Output a list of supported profiles
 * @return the profile list | NULL: error occurs
*/
jpro_profile_list* get_supported_profiles()
{
    jpro_profile_list *supported_profiles = malloc( sizeof( jpro_profile_list ) );
    if( supported_profiles == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    supported_profiles->profile_cnt = 7;
    supported_profiles->profile_names = malloc( sizeof( char* ) * supported_profiles->profile_cnt );
    if( supported_profiles->profile_names == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    supported_profiles->profile_names[0] = "Visa";
    supported_profiles->profile_names[1] = "Arrival attestation document";
    supported_profiles->profile_names[2] = "Social incurance card";
    supported_profiles->profile_names[3] = "Residence permit";
    supported_profiles->profile_names[4] = "Residence permit supplementary sheet";
    supported_profiles->profile_names[5] = "Address sticker for ID card";
    supported_profiles->profile_names[6] = "Place of residence sticker for Passport";

    supported_profiles->profile_types = malloc( sizeof( jpro_profile_type) * supported_profiles->profile_cnt );
    if( supported_profiles->profile_types == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    supported_profiles->profile_types[0] = JPRO_VISA;
    supported_profiles->profile_types[1] = JPRO_ARRIVAL_ATTESTATION_DOCUMENT;
    supported_profiles->profile_types[2] = JPRO_SOCIAL_INSURANCE_CARD;
    supported_profiles->profile_types[3] = JPRO_RESIDENCE_PERMIT;
    supported_profiles->profile_types[4] = JPRO_SUPPLEMENTARY_SHEET;
    supported_profiles->profile_types[5] = JPRO_ADDRESS_STICKER_FOR_ID_CARD;
    supported_profiles->profile_types[6] = JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT;
	return supported_profiles;
}

/**
 * @brief Output the information of a profile
 * @param[in] profile_type the profile type whose information shall be output
 * @return the profile information | NULL: unsupported profile type
*/
jpro_profile_info* get_profile_info(jpro_profile_type profile_type)
{
    if ( profile_type == JPRO_SOCIAL_INSURANCE_CARD )
    {
        return get_sic_info();
    }
    else if ( profile_type == JPRO_VISA )
    {
        return get_visa_info();
    }
    else if ( profile_type == JPRO_ARRIVAL_ATTESTATION_DOCUMENT )
    {
        return get_aad_info();
    }
    else if ( profile_type == JPRO_RESIDENCE_PERMIT )
    {
        return get_rp_info();
    }
    else if ( profile_type == JPRO_SUPPLEMENTARY_SHEET )
    {
        return get_rp_supp_sheet_info();
    }
    else if ( profile_type == JPRO_ADDRESS_STICKER_FOR_ID_CARD )
    {
        return get_addr_st_id_info();
    }
    else if ( profile_type == JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT )
    {
        return get_por_info();
    }
    else
    {
        error_handler( "Profile type not supported", UNSUPPORTED_PROFILE_TYPE );
        return 0;
    }
}

/**
 * @brief Encode a profile
 * @param[in] profile_info the profile information to be encoded
 * @return the encoded profile | NULL: error occurs
*/
jpro_data* encode_profile(jpro_profile_info* profile_info)
{
    jpro_profile_info* compare_profile = get_profile_info( profile_info->type );
    jpro_int32 matching_features = 0;
    for( jpro_int32 cmp = 0; cmp < compare_profile->feature_cnt; cmp++ )
    {
        for( jpro_int32 loop = 0; loop < profile_info->feature_cnt; loop++ )
        {
            if( strcmp( compare_profile->features[cmp].name, profile_info->features[loop].name ) == 0 &&
                      ( compare_profile->features[cmp].value_type != profile_info->features[loop].value_type ||
                        compare_profile->features[cmp].min_length != profile_info->features[loop].min_length ||
                        compare_profile->features[cmp].max_length != profile_info->features[loop].max_length ))
            {
                error_handler( "Feature data does not match profile", FEATURE_DATA_DOES_NOT_MATCH_PROFILE );
                return 0;
            }
            if( strcmp( compare_profile->features[cmp].name, profile_info->features[loop].name ) == 0 )
            {
                matching_features+=1;
            }
        }
    }
    if( matching_features != compare_profile->feature_cnt )
    {
        error_handler( "Invalid amount of mandatory features", INVALID_FEATURE_COUNT );
        return 0;
    }

    free_profile_info( compare_profile );

    if ( check_length( profile_info ) == 0 )	                  //check feature length
    {
        return NULL;
    }

    if ( check_value_type( profile_info ) == 0 )                //check feature value_type
    {
        return NULL;
    }

    if ( profile_info->type == JPRO_SOCIAL_INSURANCE_CARD )
    {
        return get_encoded_sic( profile_info );
    }
    else if ( profile_info->type == JPRO_VISA )
    {
        return get_encoded_visa( profile_info );
    }
    else if ( profile_info->type == JPRO_ARRIVAL_ATTESTATION_DOCUMENT )
    {
        return get_encoded_aad( profile_info );
    }
    else if ( profile_info->type == JPRO_RESIDENCE_PERMIT )
    {
        return get_encoded_rp( profile_info );
    }
    else if ( profile_info->type == JPRO_SUPPLEMENTARY_SHEET )
    {
        return get_encoded_rp_supp_sheet( profile_info );
    }
    else if ( profile_info->type == JPRO_ADDRESS_STICKER_FOR_ID_CARD )
    {
        return get_encoded_addr_st_id( profile_info );
    }
    else if( profile_info->type == JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT )
    {
        return get_encoded_por( profile_info );
    }
    else
    {
        error_handler( "Profile type not supported", UNSUPPORTED_PROFILE_TYPE );
        return 0;
    }
}

/**
 * @brief Append a signature to an encoded profile to create a seal
 * @param[in] encoded_profile the encoded profile signed by the signature
 * @param[in] signature the signature to be appended to the encoded profile
 * @return the created seal | NULL: error occurs
*/
jpro_data* append_signature(jpro_data* encoded_profile, jpro_data* signature)
{
    jpro_data* length_tag = get_length_tag( signature->length );

    jpro_data* signed_data = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ) * ( signature->length + encoded_profile->length + length_tag->length + 1 ) );
    if( signed_data == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    signed_data->length = signature->length + encoded_profile->length + length_tag->length + 1;

	memcpy(signed_data->data, encoded_profile->data, encoded_profile->length);
    signed_data->data[encoded_profile->length] = 0xff; //signature tag
    memcpy( signed_data->data + encoded_profile->length + 1, length_tag->data, length_tag->length );
	memcpy( signed_data->data + encoded_profile->length + length_tag->length + 1, signature->data, signature->length );

	return signed_data;
}

/**
 * @brief Output the last error message and error code
 * @param[out] error_code the error code
 * @return the error message
*/
jpro_char* get_last_error(jpro_error_code* error_code)
{
	if(error_code) *error_code = global_error_code;
	return jpro_error_msg;
}

/**
 * @brief Concatenate strings
 * @param str1 the first string
 * @param str2 the second string
 * @param str3 the third string
 * @return the concatenated string of all input strings
*/
jpro_char* cat_strings( jpro_char* buffer, jpro_char* str1, jpro_char* str2, jpro_char* str3 )
{
	strcpy(buffer, str1);
	strcat(buffer, str2);
	strcat(buffer, str3);
	return buffer;
}

/**
 * @brief Set global_error_code and jpro_error_msg
 * @param error_message the error message
 * @param error_code the error code
*/
void error_handler ( jpro_char* error_message, jpro_error_code error_code )
{
    global_error_code = error_code;
    sprintf( jpro_error_msg, "%s", error_message );
}

/**
 *@brief Create a feature_info
 *@param name the name of the feature
 *@param min_length the min length of the feature
 *@param max_length the max length of the feature
 *@param required if the feature is required
 *@param value_type type of the input value
 *@return the created feature_info
*/
jpro_feature_info create_feature_info ( jpro_char *name, jpro_int32 min_length, jpro_int32 max_length, jpro_boolean required, jpro_feature_type value_type )
{
    jpro_feature_info new_feature_info;
    new_feature_info.name = name;
    new_feature_info.min_length = min_length;
    new_feature_info.max_length = max_length;
    new_feature_info.required = required;
    new_feature_info.value_type = value_type;

    return new_feature_info;
}

/**
 *@brief Create a profile_info
 *@param type the type of the profile
 *@param header the header information of the profile
 *@param feature_cnt the amount of features of the profile
 *@param features the features of the profile
 *@param crypto the crypto information
 *@return the created profile_info | NULL: error occurs
*/
jpro_profile_info *create_profile_info ( jpro_profile_type type, jpro_int32 feature_cnt, jpro_feature_info *features, jpro_crypto_info *crypto )
{
    jpro_header_info empty_header_info;
    empty_header_info.certificate_ref = "";
    empty_header_info.signer_country = "";
    empty_header_info.signer_id = "";
    empty_header_info.issuing_country = "";

    empty_header_info.issue_date.day = "";
    empty_header_info.issue_date.month = "";
    empty_header_info.issue_date.year = "";

    empty_header_info.signature_date.day = "";
    empty_header_info.signature_date.month = "";
    empty_header_info.signature_date.year = "";

    jpro_profile_info *new_profile_info = malloc( sizeof( jpro_profile_info ) );
    if( new_profile_info == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return NULL;
    }
    new_profile_info->type = type;
    new_profile_info->header = empty_header_info;
    new_profile_info->feature_cnt = feature_cnt;
    new_profile_info->features = features;
    new_profile_info->crypto = crypto;

    return new_profile_info;
}

/**
 *@brief Create a header_info
 *@param country_id the id of the country
 *@param signer_id the id of the signer
 *@param certificate_ref the refrence to the certificate
 *@param issue_date the date of issue for the document
 *@param signature_date date of the signature creation
 *@return the created header_info
*/
jpro_header_info create_header_info ( jpro_char* issuing_country, jpro_char* signer_country, jpro_char*	signer_id, jpro_char* certificate_ref, jpro_date issue_date, jpro_date signature_date )
{
    jpro_header_info new_header_info;
    new_header_info.issuing_country = issuing_country;
    new_header_info.signer_country = signer_country;
    new_header_info.signer_id = signer_id;
    new_header_info.certificate_ref = certificate_ref;
    new_header_info.issue_date = issue_date;
    new_header_info.signature_date = signature_date;

    return new_header_info;
}

/**
 *@brief Create a crypto_info
 *@param hash_algo_cnt the amount of hash algos
 *@param hash_algos the hash algos
 *@param signature_algo_cnt the amount of signature algos
 *@param signature_algos the signature algos
 *@return the created crypto_info | NULL: error occurs
*/
jpro_crypto_info *create_crypto_info ( jpro_int32 hash_algo_cnt, jpro_crypto_algo* hash_algos, jpro_int32 signature_algo_cnt, jpro_crypto_algo*	signature_algos )
{
    jpro_crypto_info *new_crypto_info = malloc( sizeof( jpro_crypto_info ) );
    if( new_crypto_info == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return NULL;
    }
    new_crypto_info->hash_algo_cnt = hash_algo_cnt;
    new_crypto_info->hash_algos = hash_algos;
    new_crypto_info->signature_algo_cnt = signature_algo_cnt;
    new_crypto_info->signature_algos = signature_algos;

    return new_crypto_info;
}

/**
 *@brief Create a crypto_algo
 *@param algo the used algorithmus
 *@param size the size of the algo
 *@param valid_from the year from which the algo is valid
 *@param valid_till the year to which the also is valid
 *@return the created crypto_algo
*/
jpro_crypto_algo create_crypto_algo ( jpro_char* algo, jpro_int32 size, jpro_int32 valid_from, jpro_int32 valid_till )
{
    jpro_crypto_algo new_crypto_algo;
    new_crypto_algo.algo = algo;
    new_crypto_algo.size = size;
    new_crypto_algo.valid_from = valid_from;
    new_crypto_algo.valid_till = valid_till;
    return new_crypto_algo;
}

/**
 *@brief Initializes feature data as empty
 *@param feature the feature data to be initialized
*/
void initialize_empty_feature_data( jpro_feature_info *feature )
{
    feature->value_date.day = "";
    feature->value_date.month = "";
    feature->value_date.year = "";
    feature->value_int = 0;
    feature->value_string = "";
}

/**
 *@brief create a crypto_info for a profile
 *@param profile_type the profile type
 *@return the created crypto_info | NULL: error occurs
*/
jpro_crypto_info *get_crypto_info ( jpro_profile_type profile_type )
{
    if( profile_type == JPRO_SOCIAL_INSURANCE_CARD )
    {
        return get_crypto_sic();
    }
    else if ( profile_type == JPRO_VISA )
    {
        return get_crypto_visa();
    }
    else if ( profile_type == JPRO_ARRIVAL_ATTESTATION_DOCUMENT )
    {
        return get_crypto_aad();
    }
    else if ( profile_type == JPRO_RESIDENCE_PERMIT )
    {
        return get_crypto_rp();
    }
    else if ( profile_type == JPRO_SUPPLEMENTARY_SHEET )
    {
        return get_crypto_rp_supp_sheet();
    }
    else if ( profile_type == JPRO_ADDRESS_STICKER_FOR_ID_CARD )
    {
        return get_crypto_addr_st_id();
    }
    else if ( profile_type == JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT )
    {
        return get_crypto_por();
    }
    else
    {
        error_handler( "Profile type not supported", UNSUPPORTED_PROFILE_TYPE );
        return 0;
    }
}

/**
 *@brief check if a date is valid
 *@param date the date to be checked
 *@return 1: valid | NULL: error occurs
*/
jpro_boolean check_date ( jpro_date date )
{
    if ( strlen( date.year ) != 4 ||
         strlen( date.month) != 2 ||
         strlen( date.day ) !=2 )
    {
        return 0;
    }

    for ( jpro_int32 i = 0; i < 2; i++)
    {
        if ( isdigit( date.month[i] ) == 0 )
        {
            return 0;                       // non numeric char in month
        }
        else if ( isdigit( date.day[i] ) == 0 )
        {
            return 0;                       // non numeric char in day
        }
    }
    for ( jpro_int32 i = 0; i < 4; i++ )    // non numeric char in year
    {
        if (isdigit( date.year[i] ) == 0 )
        {
            return 0;
        }
    }

    if ( atoi( date.year ) > 2030 ||
         atoi( date.year ) < 1850 ||
         atoi( date.month ) > 12 ||
         atoi( date.month ) < 1 ||
         atoi( date.day ) > 31 ||
         atoi( date.day ) < 1)
    {
        return 0;
    }
    else if ( ( atoi( date.month ) == 4 ||           //check months with 30 days
                atoi( date.month ) == 6 ||
                atoi( date.month ) == 9 ||
                atoi( date.month ) == 11 ) &&
                atoi( date.day ) > 30 )
    {
        return 0;
    }
    else if( atoi( date.month ) == 2 )              //check febuary
    {
        if( (atoi(date.year)%4 == 0 && atoi(date.year)%100 != 0) || (atoi(date.year)%400 == 0) )
		{
			if( atoi( date.day ) > 29 )				//leap year
				return 0;
		}
		else
		{
			if( atoi( date.day ) > 28 )
				return 0;
		}
    }

    return 1;
}

/**
 *@brief checks the header information for length and value type
 *@param header the header to be checked
 *@return 1: success | 0: error occurs
*/
jpro_int32 check_header( jpro_header_info header )
{
    //check length
    if ( strlen( header.issuing_country ) > 3 ||
         strlen( header.issuing_country ) == 0 ) //check header data length
	{
		error_handler("Invalid value length of issuing country", INVALID_VALUE_LENGTH);
		return 0;
	}
	if( check_date( header.issue_date ) == 0 ||       //check header dates
        check_date( header.signature_date ) == 0 )
    {
        error_handler( "Invalid date in header information", INVALID_DATE );
        return 0;
    }
    if ( strlen( header.signer_country ) != 2 )
	{
        error_handler("Invalid value length of signer country", INVALID_VALUE_LENGTH);
        return 0;
	}
	if( strlen( header.signer_id ) != 2 )
    {
        error_handler("Invalid value length of signer id", INVALID_VALUE_LENGTH);
        return 0;
    }

    //check value type
    if( is_alphanum ( header.certificate_ref ) == 0 )
    {
        error_handler( "Invalid value type for certificate reference", INVALID_VALUE_TYPE );
        return 0;
    }
    if( is_alphanum( header.signer_id ) == 0 )
    {
        error_handler( "Invalid value type for signer id", INVALID_VALUE_TYPE );
        return 0;
    }

    if( header.issuing_country[0] == '<' )                                                          //to prevent "<<<" input
    {
        error_handler( "Invalid value type for issuing country", INVALID_VALUE_TYPE );
        return 0;
    }
    else if( header.issuing_country[1] == '<' && isupper( header.issuing_country[2] ) != 0 )        //to prevent inputs of form "X<X"
    {
        error_handler( "Invalid value type for issuing country", INVALID_VALUE_TYPE );
        return 0;
    }
    for( jpro_int32 loop = 0; loop < strlen( header.issuing_country ); loop++ )
    {
        if( isupper( header.issuing_country[loop] ) == 0 && header.issuing_country[loop] != '<' )
        {
            error_handler( "Invalid value type for issuing country", INVALID_VALUE_TYPE );
            return 0;
        }
    }
    for( jpro_int32 loop = 0; loop < strlen( header.signer_country ); loop++ )
    {
        if( isupper( header.signer_country[loop] ) == 0 )
        {
            error_handler( "Invalid value type for signers country", INVALID_VALUE_TYPE );
            return 0;
        }
    }
    return 1;
}

/**
 *@brief Encode header information
 *@param profile_info the profile info the header is created for
 *@return the created header | NULL: error occurs
 */
jpro_header* encode_header( jpro_profile_info* profile_info )
{
    if( check_header( profile_info->header ) == 0 )
    {
        return 0;
    }

	jpro_char* iss_cntry_buff = malloc( sizeof(jpro_char) * 4 );
    if( iss_cntry_buff == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
	strcpy( iss_cntry_buff, profile_info->header.issuing_country );
	for(jpro_int32 i=strlen( profile_info->header.issuing_country ); i<3; i++) //padding
	{
		iss_cntry_buff[i] = '<';
	}
	iss_cntry_buff[3] = '\0';

    jpro_header* new_header = malloc( sizeof( jpro_header ) );
    if( new_header == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    new_header->magic_constant = 0xDC;
    jpro_data* cntry_id = 0;
	cntry_id = c40_encode( iss_cntry_buff );
    free( iss_cntry_buff );
	if(cntry_id == 0)
	{
		return 0;
	}
    new_header->country_id[0] = cntry_id->data[0];
    new_header->country_id[1] = cntry_id->data[1];
    free( cntry_id);

    jpro_byte* buffer_issue_date = date_encode( profile_info->header.issue_date );
    jpro_byte* buffer_creat_date = date_encode( profile_info->header.signature_date );
    if ( buffer_issue_date == 0 || buffer_creat_date == 0 )
    {
        return 0;
    }
    for( jpro_int32 position = 0; position < 3; position++ )
    {
        new_header->document_issue_date[position] = buffer_issue_date[position];
        new_header->signature_creation_date[position] = buffer_creat_date[position];
    }
    free( buffer_issue_date );
    free( buffer_creat_date );

    if ( profile_info->type == JPRO_SOCIAL_INSURANCE_CARD )
    {
        new_header->version = 0x02;
        new_header->feature_ref = 0xFC;
        new_header->document_type = 0x04;
    }
    else if( profile_info->type == JPRO_VISA )
    {
        new_header->version = 0x03;
        new_header->feature_ref = 0x5D;
        new_header->document_type = 0x01;
    }
    else if( profile_info->type == JPRO_ARRIVAL_ATTESTATION_DOCUMENT )
    {
        new_header->version = 0x02;
        new_header->feature_ref = 0xFD;
        new_header->document_type = 0x02;
    }
    else if( profile_info->type == JPRO_RESIDENCE_PERMIT )
    {
        new_header->version = 0x03;
        new_header->feature_ref = 0xFB;
        new_header->document_type = 0x06;
    }
    else if( profile_info->type == JPRO_SUPPLEMENTARY_SHEET )
    {
        new_header->version = 0x03;
        new_header->feature_ref = 0xFA;
        new_header->document_type = 0x06;
    }
    else if( profile_info->type == JPRO_ADDRESS_STICKER_FOR_ID_CARD )
    {
        new_header->version = 0x03;
        new_header->feature_ref = 0xF9;
        new_header->document_type = 0x08;
    }
    else if( profile_info->type == JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT )
    {
        new_header->version = 0x03;
        new_header->feature_ref = 0xF8;
        new_header->document_type = 0x0A;
    }

    if( new_header->version == 0x03 )
    {
        jpro_int32 size_cert_ref = strlen(profile_info->header.certificate_ref);         //signer_cert_ref concenating
        if( size_cert_ref < 1 )
        {
            error_handler("Invalid value length of certificate reference", INVALID_VALUE_LENGTH);
            return 0;
        }
        jpro_char* sign_cert_ref = malloc( sizeof( jpro_char ) * ( 6 + size_cert_ref + 1 ));
        if( sign_cert_ref == 0 )
        {
            error_handler( "Out of memory", OUT_OF_MEMORY );
            return 0;
        }
        snprintf( sign_cert_ref, 6 + size_cert_ref + 1, "%s%s%02d%s", profile_info->header.signer_country, profile_info->header.signer_id, size_cert_ref, profile_info->header.certificate_ref );

        jpro_data* buffer_sign_cert_ref = c40_encode( sign_cert_ref );
        if( buffer_sign_cert_ref == 0 )
        {
            return 0;
        }
        new_header->signer_cert_ref = malloc( sizeof( jpro_byte ) * buffer_sign_cert_ref->length );
        if( new_header->signer_cert_ref == 0 )
        {
            error_handler( "Out of memory", OUT_OF_MEMORY );
            return 0;
        }
        memcpy( new_header->signer_cert_ref, buffer_sign_cert_ref->data, buffer_sign_cert_ref->length );
        new_header->signer_cert_ref_length = buffer_sign_cert_ref->length;

        free( buffer_sign_cert_ref );
        free( sign_cert_ref );
    }
    else if( new_header->version == 0x02 )
    {
        if( strlen(profile_info->header.certificate_ref) != 5 )
        {
            error_handler("Invalid value length of certificate reference", INVALID_VALUE_LENGTH);
            return 0;
        }

        jpro_char* sign_cert_ref = malloc( sizeof( jpro_char ) * 10 );
        if( sign_cert_ref == 0 )
        {
            error_handler( "Out of memory", OUT_OF_MEMORY );
            return 0;
        }
        snprintf( sign_cert_ref, 10, "%s%s%s", profile_info->header.signer_country, profile_info->header.signer_id, profile_info->header.certificate_ref );
        jpro_data* buffer_sign_cert_ref = c40_encode( sign_cert_ref );
        if( buffer_sign_cert_ref == 0 )
        {
            return 0;
        }
        new_header->signer_cert_ref = malloc( sizeof( jpro_byte ) * buffer_sign_cert_ref->length );
        if( new_header->signer_cert_ref == 0 )
        {
            error_handler( "Out of memory", OUT_OF_MEMORY );
            return 0;
        }
        memcpy( new_header->signer_cert_ref, buffer_sign_cert_ref->data, buffer_sign_cert_ref->length );
        new_header->signer_cert_ref_length = buffer_sign_cert_ref->length;

        free( buffer_sign_cert_ref );
        free( sign_cert_ref );
    }

    return new_header;
}

/**
 *@brief Get a byte sequence for the data of a header
 *@param header the header the byte sequence is created for
 *@param length the length of the header
 *@return the created bytes | NULL: error occurs
*/
jpro_byte* get_header_bytes( jpro_header* header, jpro_int32 length )
{
    jpro_byte* header_bytes = malloc( sizeof( jpro_byte ) * length );
    if( header_bytes == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }

    header_bytes[0] = header->magic_constant;
    header_bytes[1] = header->version;
    header_bytes[2] = header->country_id[0];
    header_bytes[3] = header->country_id[1];
    for( jpro_int32 i = 0; i < header->signer_cert_ref_length; i++ )
    {
        header_bytes[i+4] = header->signer_cert_ref[i];
    }
    for( jpro_int32 i = 0; i < 3; i++ )
    {
        header_bytes[i + header->signer_cert_ref_length + 4] = header->document_issue_date[i];
        header_bytes[i + header->signer_cert_ref_length + 7] = header->signature_creation_date[i];
    }
    header_bytes[header->signer_cert_ref_length + 10] = header->feature_ref;
    header_bytes[header->signer_cert_ref_length + 11] = header->document_type;

    return header_bytes;
}

/**
 *@brief Encode a date
 *@param date the date that is encoded
 *@return the encoded date | NULL: error occurs
*/
jpro_byte* date_encode( jpro_date date )
{
    jpro_byte* encoded_date = malloc( sizeof( jpro_byte ) * 3 );
    if( encoded_date == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }

    jpro_char concatenated_date[9];
    jpro_int32 cc = snprintf( concatenated_date, 9, "%s%s%s", date.month, date.day, date.year );
	if( cc <= 0)
	{
        error_handler( "Date encoding failed", DATE_ENCODING_FAILED );
        return 0;
	}
    jpro_int32 date_int = atoi( concatenated_date );

    for( jpro_int32 i = 2; i >= 0; i--)
    {
		encoded_date[i] = date_int & 0xFF;
		date_int >>= 8;
    }
    if( date_int != 0 )
    {
        error_handler( "Date encoding failed", DATE_ENCODING_FAILED );
        return 0;
    }

    return encoded_date;
}

/**
 *@brief generate data for the length tag for the length of a feature using DER-TLV (ITU-T X.690)
 *@param feature_length the length of the feature
 *@return the generated length tag data | 0: ERROR occurs
*/
jpro_data* get_length_tag( jpro_uint32 feature_length )
{
	jpro_data* length_tag;
    if( feature_length < 128 )
    {
        length_tag = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ));
        if( length_tag == 0 )
        {
            error_handler("Out of memory", OUT_OF_MEMORY );
            return 0;
        }
        length_tag->length = 1;
        length_tag->data[0] = feature_length;
    }
    else
    {
		jpro_uint32 byte_cnt = 0;	//the number of the bytes used to encode the feature length
		jpro_uint32 tmp = feature_length;
		while( tmp != 0 )
		{
			tmp >>= 8;
			byte_cnt++;
		}
		if( byte_cnt > 4 )	//the length tag consists of one to five bytes
        {
            error_handler("Invalid length tag", INVALID_LENGTH_TAG );
            return 0;
        }
		length_tag = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ) * (byte_cnt + 1) );
        if( length_tag == 0 )
        {
            error_handler("Out of memory", OUT_OF_MEMORY );
            return 0;
        }
		length_tag->data[0] = 128 + byte_cnt;	//the initial byte: 1xxxxxxx, e.g. for byte_cnt=3: 10000011
		for(jpro_int32 i=byte_cnt; i>0; i--)
		{
			length_tag->data[i] = feature_length & 0xFF;
			feature_length >>= 8;
		}
		length_tag->length = byte_cnt + 1;
    }
	return length_tag;
}

/**
 *@brief check the length of input feature data
 *@param profile_info the profile containing the feature data
 *@return 1 (true): length ok | NULL: error occurs
*/
jpro_boolean check_length ( jpro_profile_info *profile_info )
{
    for ( jpro_int32 i = 0; i < profile_info->feature_cnt; i++ )
    {
        if ( profile_info->features[i].value_type == JPRO_ALPHANUMERIC ||
             profile_info->features[i].value_type == JPRO_NUMERIC ||
             profile_info->features[i].value_type == JPRO_BINARY_UTF8 ||
             profile_info->features[i].value_type == JPRO_BINARY )
        {
            if ( profile_info->features[i].min_length > strlen( profile_info->features[i].value_string ) ||
                 profile_info->features[i].max_length < strlen( profile_info->features[i].value_string ) )
                {
					error_handler( cat_strings( jpro_error_msg, "Invalid value length of ", profile_info->features[i].name, ""), INVALID_VALUE_LENGTH);
                    return 0;
                }
        }
        else if ( profile_info->features[i].value_type == JPRO_INTEGER )
        {
            if ( profile_info->features[i].value_int > ( pow( 2, profile_info->features[i].max_length * 8 ) - 1 ) || (
                 profile_info->features[i].value_int < pow( 2, ( profile_info->features[i].min_length - 1 ) * 8 )  &&  profile_info->features[i].min_length != 1 ) ||
                 profile_info->features[i].value_int < 0 )          // for min length of 1 byte
            {
                error_handler( cat_strings( jpro_error_msg, "Invalid value length of ", profile_info->features[i].name, ""), INVALID_VALUE_LENGTH);
                return 0;
            }
        }
        else if ( profile_info->features[i].value_type == JPRO_DATE )
        {
			if ( check_date(profile_info->features[i].value_date) == 0 )
			{
                error_handler( cat_strings( jpro_error_msg, "Invalid date of ", profile_info->features[i].name, ""), INVALID_DATE );
				return 0;
			}
        }
        else // not an accepted value type
        {
			error_handler( cat_strings( jpro_error_msg, "Invalid value type of ", profile_info->features[i].name, ""), INVALID_VALUE_TYPE);
            return 0;
        }
    }
    return 1;
}

/**
 *@brief check the value type of input feature data
 *@param profile_info the profile containing the feature data
 *@return 1 (true): value_type ok | 0: error occurs
*/
jpro_boolean check_value_type( jpro_profile_info *profile_info )
{
    for ( jpro_int32 i = 0; i < profile_info->feature_cnt; i++ )
    {
        if ( profile_info->features[i].value_type == JPRO_ALPHANUMERIC )
        {
            if( is_alphanum( profile_info->features[i].value_string ) == 0 )
            {
                error_handler( cat_strings( jpro_error_msg, "Invalid value type of ", profile_info->features[i].name, ""), INVALID_VALUE_TYPE);
                return 0;
            }
        }
        else if( profile_info->features[i].value_type == JPRO_NUMERIC )
        {
            if( is_numeric( profile_info->features[i].value_string ) == 0 )
            {
                error_handler( cat_strings( jpro_error_msg, "Invalid value type of ", profile_info->features[i].name, ""), INVALID_VALUE_TYPE);
                return 0;
            }
        }
        else if ( profile_info->features[i].value_type == JPRO_BINARY_UTF8 )
        {
            if ( is_utf_8( profile_info->features[i].value_string ) == 0 )
            {
                error_handler( cat_strings( jpro_error_msg, "Invalid value type of ", profile_info->features[i].name, ""), INVALID_VALUE_TYPE);
                return 0;
            }
        }
        else if ( profile_info->features[i].value_type == JPRO_BINARY )
        {
            return 1;
        }
        else if ( profile_info->features[i].value_type == JPRO_INTEGER )
        {
			return 1;
        }
        else if ( profile_info->features[i].value_type == JPRO_DATE )
        {
            return 1; //already checked in check_length()
        }
        else
        {
            error_handler( cat_strings( jpro_error_msg, "Invalid value type of ", profile_info->features[i].name, ""), INVALID_VALUE_TYPE);
            return 0;
        }
    }
    return 1;
}

/**
 *@brief check if input string is alphanumeric
 *@param s the input string
 *@return 1 (true): is alphanumeric| NULL: error occurs
*/
jpro_boolean is_alphanum( jpro_char* s )
{
    for ( jpro_int32 j = 0; j < strlen( s ); j++ )
    {
        if ( ( !isalnum( s[j] ) && s[j] != '<' ) ||
               s[j] > 90 )                                          //1-9 & A-Z <= 90;
        {
            return 0;
        }
    }
    return 1;
}

/**
 *@brief check if input string is numerics
 *@param s the input string
 *@return 1 (true): is numeric| NULL: error occurs
*/
jpro_boolean is_numeric( jpro_char* s )
{
    for( jpro_int32 i = 0; i < strlen( s ); i++ )
    {
        if( !isdigit( s[i] ) )
        {
            return 0;
        }
    }
    return 1;
}

/**
 *@brief check if input string is utf 8 encoded
 *@param s the input string
 *@return 1 (true): is utf 8| NULL: error occurs
*/
jpro_boolean is_utf_8( jpro_char* s )
{
    const jpro_byte *bytes = (const jpro_byte *) s;

    for( jpro_int32 i = 0; i < strlen( s ); i++ )
    {
        jpro_int32 amount_ones = 0;
        jpro_int32 position = 7;
        while ( ( (bytes[i] >> position) & 0x01 )== 1 )
        {
            amount_ones++;
            position--;
        }

        if( amount_ones == 2 )
        {
            if ( ( bytes[i+1] & 0xc0 ) != 0x80 ||
                 ( bytes[i] & 0xfe ) == 0xc0 )                                  // overlong?
            {
                /* 110xxxxx 10xxxxxx */
                return 0;
            }
            else
            {
                i++;
            }
        }
        else if( amount_ones == 3 )
        {
            /* 1110xxxx 10xxxxxx 10xxxxxx */
            if (  ( bytes[i+1] & 0xc0 ) != 0x80 ||
                  ( bytes[i+2] & 0xc0 ) != 0x80 ||
                  ( bytes[i] == 0xe0 && ( bytes[1] & 0xe0 ) == 0x80 ))          // overlong?
            {
                return 0;
            }
            else
            {
                i+=2;
            }
        }
        else if( amount_ones == 4 )
        {
            /* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
            if ( ( bytes[i+1] & 0xc0 ) != 0x80 ||
                 ( bytes[i+2] & 0xc0 ) != 0x80 ||
                 ( bytes[i+3] & 0xc0 ) != 0x80 ||
                 ( bytes[i] == 0xf0 && ( bytes[1] & 0xf0 ) == 0x80 ))           // overlong?
            {
                return 0;
            }
            else
            {
                i+=3;
            }
        }
        else if( amount_ones > 4 || amount_ones == 1 )
        {
            return 0;
        }
    }
    return 1;
}

/**
 *@brief free memory of a profile_info
 *@param profile_info the profile info to be freed
*/
void free_profile_info( jpro_profile_info *profile_info )
{
	free(profile_info->crypto->hash_algos);
	free(profile_info->crypto->signature_algos);
    free(profile_info->crypto);
    free(profile_info->features);
    free(profile_info);
}

/**
 *@brief free memory of a profile_list
 *@param profile_list the profile list to be freed
*/
void free_profile_list( jpro_profile_list* profile_list)
{
	free(profile_list->profile_names);
	free(profile_list->profile_types);
	free(profile_list);
}
