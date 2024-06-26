/**
 * libjabpro - Encoding/Decoding Library of Digital Seal (BSI TR-03137)
 *
 * Copyright 2022 by Fraunhofer SIT. All rights reserved.
 * See LICENSE file for full terms of use and distribution.
 *
 * Contact: Huajian Liu <liu@sit.fraunhofer.de>
 *
 * @file c40.h
 * @brief C40 header
 */

#ifndef JABPRO_C40_H
#define JABPRO_C40_H

/**
 * @brief The C40 basic character set ('-' used as a placeholder for the shift value)
*/
/*
static const jpro_char c40_char_set[40] = {	'-', '-', '-', ' ', '0', '1', '2', '3', '4', '5',
											'6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
											'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
											'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
										  };
*/

extern jpro_data* c40_encode(jpro_char* s);
extern jpro_char* c40_decode(jpro_data* encoded_data);
extern jpro_int32 get_c40_value( jpro_char c );
extern jpro_char get_char_c40( jpro_uint16 i );


#endif
