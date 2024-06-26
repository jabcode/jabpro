/**
 * libjabpro - Encoding/Decoding Library of Digital Seal (BSI TR-03137)
 *
 * Copyright 2022 by Fraunhofer SIT. All rights reserved.
 * See LICENSE file for full terms of use and distribution.
 *
 * Contact: Huajian Liu <liu@sit.fraunhofer.de>
 *
 * @file decoder.h
 * @brief Decoder header
 */

#ifndef JABPRO_DECODER_H
#define JABPRO_DECODER_H

extern jpro_header_info* decode_profile_header(jpro_data* seal, jpro_profile_type* type, jpro_int32* header_length);
extern jpro_date date_decode( jpro_byte* encoded_date );
extern jpro_char* decode_feature( jpro_data* encoded_profile, jpro_int32 pos, jpro_int32 feature_length_enc, jpro_int32 feature_length_dec );
extern jpro_char* decode_mrz( jpro_data* encoded_profile, jpro_int32 pos, jpro_int32 feature_length_enc, jpro_int32 feature_length_dec );
extern jpro_char* get_utf8_string( jpro_data* encoded_profile, jpro_int32 pos, jpro_int32 length );
extern jpro_profile_info* get_decoded_profile_visa( jpro_data* encoded_profile, jpro_header_info* decoded_header, jpro_int32 length_header );
extern jpro_profile_info* get_decoded_profile_addr_st_id( jpro_data* encoded_profile, jpro_header_info* decoded_header, jpro_int32 length_header );
extern jpro_profile_info* get_decoded_profile_por( jpro_data* encoded_profile, jpro_header_info* decoded_header, jpro_int32 length_header );
extern jpro_profile_info* get_decoded_profile_rp( jpro_data* encoded_profile, jpro_header_info* decoded_header, jpro_int32 length_header );
extern jpro_profile_info* get_decoded_profile_rp_supp_sheet( jpro_data* encoded_profile, jpro_header_info* decoded_header, jpro_int32 length_header );
extern jpro_profile_info* get_decoded_profile_aad( jpro_data* encoded_profile, jpro_header_info* decoded_header, jpro_int32 length_header );
extern jpro_profile_info* get_decoded_profile_sic( jpro_data* encoded_profile, jpro_header_info* decoded_header, jpro_int32 length_header );
extern jpro_int32 read_length_tag( jpro_data* encoded_profile, jpro_int32* pos );

extern void free_dec_header( jpro_header_info* decoded_header );

#endif
