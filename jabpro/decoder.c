/**
 * libjabpro - Encoding/Decoding Library of Digital Seal (BSI TR-03137)
 *
 * Copyright 2022 by Fraunhofer SIT. All rights reserved.
 * See LICENSE file for full terms of use and distribution.
 *
 * Contact: Waldemar Berchtold, Huajian Liu <jabcode@sit.fraunhofer.de>
 *
 * @file decoder.c
 * @brief Profile decoding
 */

#include "jabpro.h"
#include "encoder.h"
#include "decoder.h"
#include "c40.h"
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

/**
 * @brief Decode an encoded profile header
 * @param[in]  seal the seal whose header is to be decoded, it can also be an encoded profile without the signature
 * @param[out] type the profile type of the input seal
 * @return the decoded header | NULL: error occurs
*/
jpro_header_info* decode_header(jpro_data* seal, jpro_profile_type* type)
{
	return decode_profile_header(seal, type, 0);
}

/**
 * @brief Decode an encoded profile header
 * @param[in]  seal the seal whose header is to be decoded, it can also be an encoded profile without the signature
 * @param[out] type the profile type of the input seal
 * @param[out] header_length the header length in bytes
 * @return the decoded header | NULL: error occurs
*/
jpro_header_info* decode_profile_header(jpro_data* seal, jpro_profile_type* type, jpro_int32* header_length)
{
	//reading position
	jpro_int32 pos = 0;
	//magic constant
    if( seal->data[pos++] != 0xDC )
    {
        error_handler( "Invalid header", INVALID_HEADER );
        return 0;
    }
	//version
	jpro_byte version = seal->data[pos++];
	if( version != 0x02 && version != 0x03)
	{
		error_handler( "Unsupported header version", UNSUPPORTED_HEADER_VERSION );
        return 0;
	}

    jpro_header_info* decoded_header = malloc( sizeof( jpro_header_info ) );
    if( decoded_header == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }

	//issuing country
    jpro_data* issuing_country_enc = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ) * 2 );
    if( issuing_country_enc == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    issuing_country_enc->length = 2;
    issuing_country_enc->data[0] = seal->data[pos++];
    issuing_country_enc->data[1] = seal->data[pos++];
    decoded_header->issuing_country = c40_decode( issuing_country_enc );
    if( decoded_header->issuing_country == 0 )
    {
        return 0;       //error handled in c40_decode
    }
	free( issuing_country_enc );

    if( version == 0x02 )         //header version 3
    {
		//decode signer identifier and certificate reference
        jpro_data* sign_cert_ref = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ) * 6 );
        if( sign_cert_ref == 0 )
        {
            error_handler( "Out of memory", OUT_OF_MEMORY );
            return 0;
        }
        sign_cert_ref->length = 6;
        memcpy( sign_cert_ref->data, seal->data + pos, sign_cert_ref->length );
		pos += sign_cert_ref->length;
        jpro_char* sign_cert_ref_dec = c40_decode( sign_cert_ref );
        if( sign_cert_ref_dec == 0 )
        {
            return 0;       //error handled in c40_decode
        }
        decoded_header->signer_country = malloc( sizeof( jpro_char ) * 3 );
        decoded_header->signer_id = malloc( sizeof( jpro_char ) * 3 );
        decoded_header->certificate_ref = malloc( sizeof( jpro_char ) * 6 );
        if( decoded_header->signer_country == 0 || decoded_header->signer_id == 0 || decoded_header->certificate_ref == 0 )
        {
            error_handler( "Out of memory" , OUT_OF_MEMORY );
            return 0;
        }
        snprintf( decoded_header->signer_country, 3, "%c%c", sign_cert_ref_dec[0], sign_cert_ref_dec[1] );
        snprintf( decoded_header->signer_id, 3, "%c%c", sign_cert_ref_dec[2], sign_cert_ref_dec[3] );
		snprintf( decoded_header->certificate_ref, 6, "%s", sign_cert_ref_dec + 4);
		free( sign_cert_ref );
		free( sign_cert_ref_dec );
    }
    else if( version == 0x03 )    //header version 4
    {
		//decode signer identifier + the length of certificate reference
		jpro_data* sign_ref = malloc( sizeof(jpro_data) + sizeof(jpro_byte) * 4 );
		if( sign_ref == 0 )
		{
			error_handler( "Out of memory", OUT_OF_MEMORY );
            return 0;
		}
		sign_ref->length = 4;
		memcpy(sign_ref->data, seal->data + pos, sign_ref->length);
		pos += sign_ref->length;
		jpro_char* sign_ref_dec = c40_decode( sign_ref );
		if( sign_ref_dec == 0 )
		{
			return 0;
		}
		decoded_header->signer_country = malloc( sizeof( jpro_char ) * 3 );
        decoded_header->signer_id = malloc( sizeof( jpro_char ) * 3 );
		if( decoded_header->signer_country == 0 || decoded_header->signer_id == 0)
        {
            error_handler( "Out of memory" , OUT_OF_MEMORY );
            return 0;
        }
        snprintf( decoded_header->signer_country, 3, "%c%c", sign_ref_dec[0], sign_ref_dec[1] );
        snprintf( decoded_header->signer_id, 3, "%c%c", sign_ref_dec[2], sign_ref_dec[3] );
		jpro_int32 cert_ref_length = (sign_ref_dec[4]-48) * 16 + (sign_ref_dec[5]-48);	//get the length of certificate reference
		free( sign_ref );
		free( sign_ref_dec );

		//decode certiface reference
		jpro_int32 cert_ref_c40_length = (cert_ref_length/3 + cert_ref_length%3 > 0 ? 1 : 0 ) * 2;
		jpro_data* cert_ref_enc = malloc( sizeof(jpro_data) + sizeof(jpro_byte) * cert_ref_c40_length );
		if( cert_ref_enc == 0 )
		{
			error_handler( "Out of memory", OUT_OF_MEMORY );
            return 0;
		}
		cert_ref_enc->length = cert_ref_c40_length;
		memcpy(cert_ref_enc->data, seal->data + pos, cert_ref_enc->length);
		pos += cert_ref_enc->length;
		decoded_header->certificate_ref = c40_decode( cert_ref_enc );
		if( decoded_header->certificate_ref == 0 )
		{
			return 0;
		}
		free(cert_ref_enc);
    }

	//decode document issue date
	decoded_header->issue_date = date_decode( seal->data + pos );
	pos += 3;
	if( strcmp( decoded_header->issue_date.day, "" ) == 0 )
	{
		return 0;       //error handled in date_decode
	}
	//decode signature creation date
	decoded_header->signature_date = date_decode( seal->data + pos );
	pos += 3;
	if( strcmp( decoded_header->signature_date.day, "" ) == 0 )
	{
		return 0;       //error handled in date_decode
	}
	//document feature definition reference
	jpro_byte feature_ref = seal->data[pos++];
	//document type category
	jpro_byte document_type = seal->data[pos++];

	//set profile type
	if( version == 0x02 && feature_ref == 0xFD && document_type == 0x02 )
	{
		*type = JPRO_ARRIVAL_ATTESTATION_DOCUMENT;
	}
	else if( version == 0x02 && feature_ref == 0xFC && document_type == 0x04 )
	{
		*type = JPRO_SOCIAL_INSURANCE_CARD;
	}
	else if( version == 0x03 && feature_ref == 0x5D && document_type == 0x01 )
	{
		*type = JPRO_VISA;
	}
	else if( version == 0x03 && feature_ref == 0xFB && document_type == 0x06 )
	{
		*type = JPRO_RESIDENCE_PERMIT;
	}
	else if( version == 0x03 && feature_ref == 0xFA && document_type == 0x06 )
    {
        *type = JPRO_SUPPLEMENTARY_SHEET;
    }
	else if( version == 0x03 && feature_ref == 0xF9 && document_type == 0x08 )
	{
		*type = JPRO_ADDRESS_STICKER_FOR_ID_CARD;
	}
	else if( version == 0x03 && feature_ref == 0xF8 && document_type == 0x0A )
	{
		*type = JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT;
	}
	else
	{
		error_handler( "Unknown profile type in header", UNKNOWN_PROFILE_TYPE );
		return 0;
	}
	//set the header length
	if(header_length)
	{
		*header_length = pos;
	}

	return decoded_header;
}

/**
 * @brief Parse a seal to an encoded profile and a signature
 * @param[in]  seal the seal to be parsed
 * @param[out] encoded_profile the encoded profile section of the seal
 * @param[out] signature the signature section of the seal
 * @param[in]  signature_length the length of the signature
 * @return 1: success | 0: error occurs
*/
jpro_int32 parse_seal(jpro_data* seal, jpro_data** encoded_profile, jpro_data** signature, jpro_int32 signature_length )
{
    jpro_int32 length_tag_size;
	if( signature_length <= 0 )
	{
		error_handler( "Invalid signature length", INVALID_SIGNATURE_LENGTH );
        return 0;
	}
	else if( signature_length <=127 )
	{
		length_tag_size = 1;
	}
	else
	{
		jpro_uint32 byte_cnt = 0;	//the number of the bytes used to encode the signature length
		jpro_uint32 tmp = signature_length;
		while( tmp != 0 )
		{
			tmp >>= 8;
			byte_cnt++;
		}
		length_tag_size = byte_cnt + 1; //plus the initial byte of the length tag
	}

	jpro_int32 signature_tag_position = seal->length - signature_length - length_tag_size - 1;
    if( seal->data[signature_tag_position] != 0xff )
    {
        error_handler( "Signature tag not found", SIGNATURE_TAG_NOT_FOUND );
        return 0;
    }
    jpro_int32 length_tag_position = signature_tag_position + 1;
    if( read_length_tag( seal, &length_tag_position ) != signature_length )
    {
        error_handler( "Invalid signature length", INVALID_SIGNATURE_LENGTH );
        return 0;
    }

    *encoded_profile = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ) * ( seal->length - signature_length - length_tag_size - 1 ) );
    *signature = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ) * signature_length );
    if( *encoded_profile == 0 || *signature == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    (*encoded_profile)->length = seal->length - signature_length - length_tag_size - 1;
    memcpy( (*encoded_profile)->data, seal->data, (*encoded_profile)->length );

    (*signature)->length = signature_length;
    memcpy( (*signature)->data, seal->data + (*encoded_profile)->length + 1 + length_tag_size, (*signature)->length );

	return 1;
}

/**
 * @brief Decode an encoded profile
 * @param[in] encoded_profile the encoded profile to be decoded, it can also be a complete seal
 * @return the decoded profile | NULL: error occurs
*/
jpro_profile_info* decode_profile(jpro_data* encoded_profile)
{
    jpro_profile_type profile_type;
	jpro_int32 header_length;

    jpro_header_info* header = decode_profile_header( encoded_profile, &profile_type, &header_length );
    if( header == 0 )
    {
        return 0;
    }

    if( profile_type == JPRO_VISA )
    {
        return ( get_decoded_profile_visa( encoded_profile, header, header_length ));
    }
    else if( profile_type == JPRO_RESIDENCE_PERMIT )
    {
        return ( get_decoded_profile_rp( encoded_profile, header, header_length ));
    }
    else if( profile_type == JPRO_SUPPLEMENTARY_SHEET )
    {
        return ( get_decoded_profile_rp_supp_sheet( encoded_profile, header, header_length ));
    }
    else if( profile_type == JPRO_SOCIAL_INSURANCE_CARD )
    {
        return ( get_decoded_profile_sic( encoded_profile, header, header_length ));
    }
    else if( profile_type == JPRO_ARRIVAL_ATTESTATION_DOCUMENT )
    {
        return ( get_decoded_profile_aad( encoded_profile, header, header_length ));
    }
    else if( profile_type == JPRO_ADDRESS_STICKER_FOR_ID_CARD )
    {
        return ( get_decoded_profile_addr_st_id( encoded_profile, header, header_length ));
    }
    else if( profile_type == JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT )
    {
        return ( get_decoded_profile_por( encoded_profile, header, header_length ));
    }
    else
    {
        error_handler( "Unsupported profile type", UNSUPPORTED_PROFILE_TYPE );
        return 0;
    }
}

/**
 *@brief decodes a encoded date
 *@param encoded_date the encoded date
 *@return the decoded date | ERROR: return an empty date
*/
jpro_date date_decode( jpro_byte* encoded_date )
{
    jpro_date decoded_date;
    jpro_date empty_date;
    empty_date.day = "";
    empty_date.month = "";
    empty_date.year = "";

	jpro_char date_str[9];
	jpro_int32 date_int = (encoded_date[0] << 16) + (encoded_date[1] << 8) + encoded_date[2];
	snprintf( date_str, 9, "%08d", date_int);	//mmddyyyy

    decoded_date.month = malloc( sizeof( jpro_char ) * 3);
    decoded_date.day = malloc( sizeof( jpro_char ) * 3);;
    decoded_date.year = malloc( sizeof( jpro_char ) * 5);;
    if( decoded_date.month == 0 || decoded_date.day == 0 || decoded_date.year == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return empty_date;
    }

    snprintf( decoded_date.month, 3, "%c%c", date_str[0], date_str[1] );
    snprintf( decoded_date.day, 3, "%c%c", date_str[2], date_str[3] );
    snprintf( decoded_date.year, 5, "%s", date_str + 4 );

    return decoded_date;
}

/**
 *@brief decodes a single feature of an encoded profile
 *@param encoded_profile the encoded profile
 *@param pos the position at which the feature is in the raw data
 *@param feature_length_enc the length of the encoded feature
 *@param feature_length_dec the length of the decoded feature
 *@return the decoded feature | NULL: error occurs
*/
jpro_char* decode_feature( jpro_data* encoded_profile, jpro_int32 pos, jpro_int32 feature_length_enc, jpro_int32 feature_length_dec )
{
    if( encoded_profile->length < pos + feature_length_enc )
    {
        error_handler( "Invalid length: Not enough bytes to decode feature", INVALID_VALUE_LENGTH );
        return 0;
    }

    jpro_data* feature_enc = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ) * ( feature_length_enc + 1 ));
    if( feature_enc == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    feature_enc->length = feature_length_enc;
    memcpy( feature_enc->data, encoded_profile->data + pos, feature_length_enc );
    jpro_char* feature_dec = c40_decode( feature_enc );
    if( feature_dec == 0 )
    {
        return 0;
    }

    free( feature_enc );

    return feature_dec;
}

/**
 *@brief decode a mrz of a profile
 *@param encoded_profile the encoded profile data that includes the mrz
 *@param pos the position at which the mrz starts
 *@param feature_length_enc the length of the encoded mrz
 *@param feature_length_dec the length of the decoded mrz
 *@return the decoded mrz | NULL: error occurs
*/
jpro_char* decode_mrz( jpro_data* encoded_profile, jpro_int32 pos, jpro_int32 feature_length_enc, jpro_int32 feature_length_dec )
{
    if( encoded_profile->length < pos + feature_length_enc )
    {
        error_handler( "Invalid length: Not enough bytes to decode mrz", INVALID_VALUE_LENGTH );
        return 0;
    }

    jpro_data* mrz_encoded = malloc( sizeof( jpro_data ) + sizeof( jpro_byte ) * (feature_length_enc + 1) );
    if( mrz_encoded == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    mrz_encoded->length = feature_length_enc;
    memcpy( mrz_encoded->data, encoded_profile->data + pos, feature_length_enc );
    jpro_char* mrz_decoded = c40_decode( mrz_encoded );
    if( mrz_decoded == 0 )
    {
        return 0;
    }

    free( mrz_encoded );

    return mrz_decoded;
}

/**
 *@brief gets a utf-8 encoded string from raw data
 *@param encoded_profile the raw profile data
 *@param pos the position at which the utf-8 data starts
 *@param length the length of the string
 *@return the utf-8 string | NULL: error occurs
*/
jpro_char* get_utf8_string( jpro_data* encoded_profile, jpro_int32 pos, jpro_int32 length )
{
    if( encoded_profile->length < pos + length )                    //check if remaining bytes in encoded profile are sufficient to read string of length 'length'
    {
        error_handler( "Invalid length: Not enough bytes to read utf8-string", INVALID_VALUE_LENGTH );
        return 0;
    }

    jpro_char* utf8_str = malloc( sizeof( jpro_char ) * ( length + 1 ));
    if( utf8_str == 0 )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    for( jpro_int32 position = 0; position < length; position++ )
    {
        sprintf( utf8_str + position, "%c", encoded_profile->data[pos + position] );
    }

    return utf8_str;
}

/**
 *@brief read a length tag
 *@param encoded_profile the encoded profile to read from
 *@param[out] pos the position to start reading, returning the position where reading stopped
 *@return the length value that was stored in a length tag | 0: ERROR occurs
*/
jpro_int32 read_length_tag( jpro_data* encoded_profile, jpro_int32* pos )
{
    if( encoded_profile->data[*pos] < 128 )
    {
        return( encoded_profile->data[*pos] );
    }
    else
    {
        jpro_int32 tag_length = encoded_profile->data[*pos] - 128;
        if( tag_length == 0 || tag_length > 4 )
        {
            error_handler( "Invalid length tag", INVALID_LENGTH_TAG );
            return 0;
        }
        jpro_int32 feature_length = 0;
        for( jpro_int32 loop = (*pos + tag_length); loop > *pos; loop-- )
        {
            jpro_int32 val = encoded_profile->data[loop];
			feature_length += val << ((tag_length - (loop - *pos)) * 8 );
        }
        *pos = *pos + tag_length;
        return feature_length;
    }
}

/**
 *@brief frees memory for a header_info of a decoded header
 *@param decoded_header the header for which memory is freed
*/
void free_dec_header( jpro_header_info* decoded_header )
{
    free( decoded_header->signer_id );
    free( decoded_header->signer_country );
    free( decoded_header->issuing_country );
    free( decoded_header->certificate_ref);
    free( decoded_header->signature_date.day);
    free( decoded_header->signature_date.month);
    free( decoded_header->signature_date.year);
    free( decoded_header->issue_date.day );
    free( decoded_header->issue_date.month );
    free( decoded_header->issue_date.year );
    free( decoded_header );
}

/**
 *@brief free allocated string values of features
 *@param profile_info the profile containing the features
*/
void free_feature_values( jpro_profile_info *profile_info )
{
    for( jpro_int32 i = 0; i < profile_info->feature_cnt; i++ )
    {
        if( profile_info->features[i].value_type == JPRO_ALPHANUMERIC ||
            profile_info->features[i].value_type == JPRO_NUMERIC ||
            profile_info->features[i].value_type == JPRO_BINARY ||
            profile_info->features[i].value_type == JPRO_BINARY_UTF8 )
        {
            free( profile_info->features[i].value_string );
        }
    }
}

/**
 *@brief free memory of strings in header_info
 *@param header the header
 */
void free_header_info_data( jpro_header_info header )
{
    free(header.issue_date.year);
    free(header.issue_date.month);
    free(header.issue_date.day);
    free(header.signature_date.year);
    free(header.signature_date.month);
    free(header.signature_date.day);
    free(header.signer_id);
    free(header.signer_country);
    free(header.issuing_country);
    free(header.certificate_ref);
}
