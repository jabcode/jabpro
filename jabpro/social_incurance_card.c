/**
 * libjabpro - Encoding/Decoding Library of Digital Seal (BSI TR-03137)
 *
 * Copyright 2022 by Fraunhofer SIT. All rights reserved.
 * See LICENSE file for full terms of use and distribution.
 *
 * Contact: Waldemar Berchtold, Huajian Liu <jabcode@sit.fraunhofer.de>
 *
 * @file social_incurance_card.c
 * @brief Specific functions for social incurace card
 */

#include "jabpro.h"
#include "encoder.h"
#include "decoder.h"
#include "c40.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

const jpro_int32 jpro_number_features_sic = 4;

/**
 *@brief get data for an utf8-string
 *@param utf8-string the utf8-string to get data for
 *@return utf8 data | 0: ERROR occurs
*/
jpro_data* get_utf8_data( jpro_char* utf8_string )
{
    jpro_data* utf8_data = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ) * strlen( utf8_string ));
    if( utf8_data == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    utf8_data->length = strlen( utf8_string );

    for( jpro_int32 loop = 0; loop < utf8_data->length; loop++ )
    {
        utf8_data->data[loop] = utf8_string[loop];
    }
    return utf8_data;
}


/**
 *@brief creates profile_info for social incurance card
 *@return the created profile_info | NULL: error occurs
*/
jpro_profile_info *get_sic_info()
{
    jpro_feature_info *features = malloc( sizeof( jpro_feature_info ) * jpro_number_features_sic );
    if( features == NULL )                                                                                                  //error check
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    features[0] = create_feature_info ( "Social insurance number", 12, 12, 1, JPRO_ALPHANUMERIC );
    features[1] = create_feature_info ( "Surname", 1, 90, 1, JPRO_BINARY_UTF8 );
    features[2] = create_feature_info ( "First name", 1, 90, 1, JPRO_BINARY_UTF8 );;
    features[3] = create_feature_info ( "Name at birth", 1, 90, 1, JPRO_BINARY_UTF8 );                                      // set as required check difference in encode_profile

    for( jpro_int32 i = 0; i < jpro_number_features_sic; i++ )
    {
        initialize_empty_feature_data( &features[i] );
    }

    jpro_crypto_info *crypto = get_crypto_info( JPRO_SOCIAL_INSURANCE_CARD );
	if( crypto == NULL )
	{
		return 0;
	}
    return ( create_profile_info( JPRO_SOCIAL_INSURANCE_CARD, jpro_number_features_sic, features, crypto ));
}

/**
 *@brief creates encoded data for social incurance card
 *@param profile_info the profile information to be encoded
 *@return the created encoded data | NULL: error occurs
*/
jpro_data *get_encoded_sic( jpro_profile_info *profile_info )
{
    jpro_header* encoded_header = encode_header( profile_info );
    if( encoded_header == 0 )
    {
        return 0;
    }
    jpro_data* sin_enc = 0;
    jpro_data* surname = 0;
    jpro_data* first_name = 0;
    jpro_data* name_at_birth = 0;

    for( jpro_int32 loop = 0; loop < profile_info->feature_cnt; loop++ )
    {
        if( strcmp( profile_info->features[loop].name, "Social insurance number" ) == 0 )
        {
            sin_enc = c40_encode( profile_info->features[loop].value_string );
            if( sin_enc == 0 )
            {
                return 0;
            }
        }
        else if( strcmp( profile_info->features[loop].name, "Surname" ) == 0 )
        {
            surname = get_utf8_data( profile_info->features[loop].value_string );
            if( surname == 0 )
            {
                return 0;
            }
        }
        else if( strcmp( profile_info->features[loop].name, "First name" ) == 0 )
        {
            first_name = get_utf8_data( profile_info->features[loop].value_string );
            if( first_name == 0 )
            {
                return 0;
            }
        }
        else if( strcmp( profile_info->features[loop].name, "Name at birth" ) == 0 )
        {
            name_at_birth = get_utf8_data( profile_info->features[loop].value_string );
            if( name_at_birth == 0 )
            {
                return 0;
            }
        }
        else
        {
            //additional features
        }
    }
    if( sin_enc == 0 || surname == 0 || first_name == 0 )
    {
        error_handler( "Required feature not found", REQUIRED_FEATURE_NOT_FOUND );
        return 0;
    }
    jpro_int32 filler_tag_len = 0;
    if( memcmp( name_at_birth->data, surname->data, name_at_birth->length ) != 0 )
    {
        filler_tag_len = 2;
    }
    else
    {
        name_at_birth->length = 0;
    }

    const jpro_int32 header_length = encoded_header->signer_cert_ref_length + 12;
    const jpro_int32 length_of_tags = (jpro_number_features_sic - 1) * 2 + filler_tag_len;
    const jpro_int32 length_features = sin_enc->length + first_name->length + surname->length + name_at_birth->length + length_of_tags;

    jpro_data* encoded_profile_sic = malloc( sizeof( jpro_data ) + sizeof ( jpro_byte ) * ( header_length + length_features + 1 ));
    if( encoded_profile_sic == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    encoded_profile_sic->length = header_length + length_features;

    //header
    jpro_byte* header_bytes = get_header_bytes( encoded_header, header_length );
    if( header_bytes == 0 )
    {
        return 0;
    }
    memcpy( encoded_profile_sic->data, header_bytes, header_length );

    //message zone
    encoded_profile_sic->data[header_length] = 0x01;
    encoded_profile_sic->data[header_length + 1] = sin_enc->length;
    memcpy( encoded_profile_sic->data + header_length + 2, sin_enc->data, sin_enc->length );
    encoded_profile_sic->data[header_length + sin_enc->length + 2] = 0x02;
    encoded_profile_sic->data[header_length + sin_enc->length + 3] = surname->length;
    memcpy( encoded_profile_sic->data + header_length + sin_enc->length + 4, surname->data, surname->length );
    encoded_profile_sic->data[header_length + sin_enc->length + surname->length + 4] = 0x03;
    encoded_profile_sic->data[header_length + sin_enc->length + surname->length + 5] = first_name->length;
    memcpy( encoded_profile_sic->data + header_length + sin_enc->length + surname->length + 6, first_name->data, first_name->length );
    if( name_at_birth->length != 0 )
    {
        encoded_profile_sic->data[header_length + sin_enc->length + surname->length + first_name->length + 6] = 0x04;
        encoded_profile_sic->data[header_length + sin_enc->length + surname->length + first_name->length + 7] = name_at_birth->length;
        memcpy( encoded_profile_sic->data + header_length + sin_enc->length + surname->length + first_name->length + 8, name_at_birth->data, name_at_birth->length );
    }

    free( name_at_birth );
    free( encoded_header->signer_cert_ref );
    free( encoded_header );
    free( sin_enc );
    free( surname );
    free( first_name );
    free( header_bytes );

    return encoded_profile_sic;
}

/**
 *@brief creates decoded profile_info for social incurance card profile
 *@param encoded_profile the encoded data to be decoded
 *@param decoded_header the decoded header for the profile
 *@param length_header the length of the encoded header
 *@return the created decoded profile_info| NULL: error occurs
*/
jpro_profile_info* get_decoded_profile_sic( jpro_data* encoded_profile, jpro_header_info* decoded_header, jpro_int32 length_header )
{
    jpro_profile_info* decoded_profile = get_profile_info( JPRO_SOCIAL_INSURANCE_CARD );
    if( decoded_profile == 0 )
    {
        return 0;
    }

    decoded_profile->header.certificate_ref = decoded_header->certificate_ref;
    decoded_profile->header.issue_date = decoded_header->issue_date;
    decoded_profile->header.issuing_country = decoded_header->issuing_country;
    decoded_profile->header.signature_date = decoded_header->signature_date;
    decoded_profile->header.signer_country = decoded_header->signer_country;
    decoded_profile->header.signer_id = decoded_header->signer_id;

    free(decoded_header);

    jpro_int32 nr_required_features = 0;
    jpro_int32 pos_bytes = length_header;
    do
    {
        if( encoded_profile->data[pos_bytes] == 0x01 )
        {
            jpro_int32 length_sin = encoded_profile->data[++pos_bytes];
            decoded_profile->features[0].value_string = decode_mrz( encoded_profile, ++pos_bytes, length_sin, 12 );
            if( decoded_profile->features[0].value_string == 0 )
            {
                return 0;
            }
            pos_bytes+=length_sin;
            nr_required_features++;
        }
        else if( encoded_profile->data[pos_bytes] == 0x02 )
        {
            jpro_int32 length_surname = encoded_profile->data[++pos_bytes];
            decoded_profile->features[1].value_string = get_utf8_string( encoded_profile, ++pos_bytes, length_surname );
            if( decoded_profile->features[1].value_string == 0 )
            {
                return 0;
            }
            pos_bytes+=length_surname;
            nr_required_features++;
        }
        else if( encoded_profile->data[pos_bytes] == 0x03 )
        {
            jpro_int32 length_first_name = encoded_profile->data[++pos_bytes];
            decoded_profile->features[2].value_string = get_utf8_string( encoded_profile, ++pos_bytes, length_first_name );
            if( decoded_profile->features[2].value_string == 0 )
            {
                return 0;
            }
            pos_bytes+=length_first_name;
            nr_required_features++;
        }
        else if( encoded_profile->data[pos_bytes] == 0x04 )
        {
            jpro_int32 length_name_at_birth = encoded_profile->data[++pos_bytes];
            decoded_profile->features[3].value_string = get_utf8_string( encoded_profile, ++pos_bytes, length_name_at_birth );
            if( decoded_profile->features[3].value_string == 0 )
            {
                return 0;
            }
            pos_bytes+=length_name_at_birth;
        }
        else
        {
            //unknown feature
            jpro_int32 unknown_feature_lenght = encoded_profile->data[++pos_bytes];
            pos_bytes+=unknown_feature_lenght;
        }
    } while( pos_bytes < encoded_profile->length && encoded_profile->data[pos_bytes] != 0xff );

    if( nr_required_features != decoded_profile->feature_cnt - 1 )
    {
        error_handler( "Required feature not found", REQUIRED_FEATURE_NOT_FOUND );
        return 0;
    }

    return decoded_profile;
}

/**
 *@brief create a crypto_info for social insurance card
 *@return the created crypto_info | NULL: error occurs
*/
jpro_crypto_info *get_crypto_sic()
{
    jpro_int32 hash_algo_count = 1;
    jpro_int32 sign_algo_count = 1;
    jpro_crypto_algo* hash_algos = malloc( sizeof( jpro_crypto_algo ) * hash_algo_count );
    jpro_crypto_algo* signature_algos = malloc( sizeof( jpro_crypto_algo ) * sign_algo_count );
    if( hash_algos == NULL ||
        signature_algos == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    hash_algos[0] = create_crypto_algo( HASH_ALGO, HASH_SIZE, VALID_FROM, VALID_TIL );
    signature_algos[0] = create_crypto_algo( SIGN_ALGO, SIGN_SIZE, VALID_FROM, VALID_TIL );

    return ( create_crypto_info( hash_algo_count, hash_algos, sign_algo_count, signature_algos ));
}
