/**
 * libjabpro - Encoding/Decoding Library of Digital Seal (BSI TR-03137)
 *
 * Copyright 2022 by Fraunhofer SIT. All rights reserved.
 * See LICENSE file for full terms of use and distribution.
 *
 * Contact: Huajian Liu <liu@sit.fraunhofer.de>
 *
 * @file residence_permit.c
 * @brief Specific functions for residence permit profile
 */

#include "jabpro.h"
#include "encoder.h"
#include "decoder.h"
#include "c40.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

const jpro_int32 jpro_number_features_rp = 2;

/**
 *@brief creates profile_info for residence permit
 *@return the created profile_info | NULL: error occurs
*/
jpro_profile_info *get_rp_info()
{
    jpro_feature_info *features = malloc( sizeof( jpro_feature_info ) * jpro_number_features_rp );
    if( features == NULL )                                                                                                  //error check
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    features[0] = create_feature_info ( "Machine readable zone", 72, 72, 1, JPRO_ALPHANUMERIC );                            //TD2-MROTD
    features[1] = create_feature_info ( "Passport number", 9, 9, 1, JPRO_ALPHANUMERIC );

    for( jpro_int32 i = 0; i < jpro_number_features_rp; i++ )
    {
        initialize_empty_feature_data( &features[i] );
    }

    jpro_crypto_info *crypto = get_crypto_info( JPRO_RESIDENCE_PERMIT );
    if( crypto == 0 )
    {
        return 0;
    }

    return ( create_profile_info( JPRO_RESIDENCE_PERMIT, jpro_number_features_rp, features, crypto ));
}

/**
 *@brief creates encoded data for residence permit
 *@param profile_info the profile information to be encoded
 *@return the created encoded data | NULL: error occurs
*/
jpro_data *get_encoded_rp( jpro_profile_info *profile_info )
{
    jpro_header* encoded_header = encode_header( profile_info );
    if( encoded_header == 0 )
    {
        return 0;
    }
    jpro_data* mrz_encoded = 0;
    jpro_data* passport_number_encoded = 0;

    for( jpro_int32 loop = 0; loop < profile_info->feature_cnt; loop++ )
    {
        if( strcmp( profile_info->features[loop].name, "Machine readable zone" ) == 0 )
        {
            mrz_encoded = c40_encode( profile_info->features[loop].value_string );
            if( mrz_encoded == 0 )
            {
                return 0;
            }
        }
        else if( strcmp( profile_info->features[loop].name, "Passport number" ) == 0 )
        {
            passport_number_encoded = c40_encode( profile_info->features[loop].value_string );
            if( passport_number_encoded == 0 )
            {
                return 0;
            }
        }
        else
        {
            //additional features
        }
    }
    if( passport_number_encoded == 0 || mrz_encoded == 0 )
    {
        error_handler( "Required feature not found", REQUIRED_FEATURE_NOT_FOUND );
        return 0;
    }

    jpro_data* length_tag_mrz = get_length_tag( mrz_encoded->length );
    jpro_data* length_tag_pss_nr = get_length_tag( passport_number_encoded->length );
    if( length_tag_mrz == 0 || length_tag_pss_nr == 0 )
    {
        return 0;
    }

    const jpro_int32 length_of_tags = jpro_number_features_rp + length_tag_mrz->length + length_tag_pss_nr->length;
    const jpro_int32 length_features = mrz_encoded->length + passport_number_encoded->length + length_of_tags;
    const jpro_int32 header_length = encoded_header->signer_cert_ref_length + 12;

    jpro_data* encoded_profile_rp = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ) * ( header_length + length_features + 1 ));
    if ( encoded_profile_rp == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    encoded_profile_rp->length = header_length + length_features;

    //header
    jpro_byte* header_bytes = get_header_bytes( encoded_header, header_length );
    if( header_bytes == 0 )
    {
        return 0;
    }
    memcpy( encoded_profile_rp->data, header_bytes, header_length );

    //message zone
    encoded_profile_rp->data[header_length] = 0x02;
    memcpy( encoded_profile_rp->data + header_length + 1, length_tag_mrz->data, length_tag_mrz->length );
    memcpy( encoded_profile_rp->data + header_length + length_tag_mrz->length + 1, mrz_encoded->data, mrz_encoded->length );
    encoded_profile_rp->data[header_length + length_tag_mrz->length + mrz_encoded->length + 1] = 0x03;
    memcpy( encoded_profile_rp->data + header_length + length_tag_mrz->length + mrz_encoded->length + 2, length_tag_pss_nr->data, length_tag_pss_nr->length );
    memcpy( encoded_profile_rp->data + header_length + length_tag_mrz->length + mrz_encoded->length + length_tag_pss_nr->length + 2, passport_number_encoded->data, passport_number_encoded->length );

    free( encoded_header->signer_cert_ref );
    free( encoded_header );
    free( mrz_encoded );
    free( length_tag_mrz );
    free( passport_number_encoded );
    free( length_tag_pss_nr );
    free( header_bytes );

    return encoded_profile_rp;
}

/**
 *@brief creates decoded profile_info for residence permit
 *@param encoded_profile the encoded data to be decoded
 *@param decoded_header the decoded header for the profile
 *@param length_header the length of the encoded header
 *@return the created decoded profile_info| NULL: error occurs
*/
jpro_profile_info* get_decoded_profile_rp( jpro_data* encoded_profile, jpro_header_info* decoded_header, jpro_int32 length_header )
{
    jpro_profile_info* decoded_profile = get_profile_info( JPRO_RESIDENCE_PERMIT );
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
        if( encoded_profile->data[pos_bytes] == 0x02 )
        {
            pos_bytes++;
            jpro_int32 length_mrz = read_length_tag( encoded_profile, &pos_bytes );
            decoded_profile->features[0].value_string = decode_mrz( encoded_profile, ++pos_bytes, length_mrz, 72 );
            if( decoded_profile->features[0].value_string == 0 )
            {
                return 0;
            }
            pos_bytes+=length_mrz;
            nr_required_features++;
        }
        else if( encoded_profile->data[pos_bytes] == 0x03 )
        {
            pos_bytes++;
            jpro_int32 length_passport_num = read_length_tag( encoded_profile, &pos_bytes );
            decoded_profile->features[1].value_string = decode_feature( encoded_profile, ++pos_bytes, length_passport_num, 9 );
            if( decoded_profile->features[1].value_string == 0 )
            {
                return 0;
            }
            pos_bytes+=length_passport_num;
            nr_required_features++;
        }
        else
        {
            //unknown feature
            pos_bytes++;
            jpro_int32 unknown_feature_lenght = read_length_tag( encoded_profile, &pos_bytes );
            pos_bytes+=unknown_feature_lenght;
        }
    } while( pos_bytes < encoded_profile->length && encoded_profile->data[pos_bytes] != 0xff );

    if( nr_required_features != decoded_profile->feature_cnt )
    {
        error_handler( "Required feature not found", REQUIRED_FEATURE_NOT_FOUND );
        return 0;
    }

    return decoded_profile;
}

/**
 *@brief create a crypto_info for residence permit
 *@return the created crypto_info | NULL: error occurs
*/
jpro_crypto_info *get_crypto_rp()
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
