/**
 * libjabpro - Encoding/Decoding Library of Digital Seal (BSI TR-03137)
 *
 * Copyright 2022 by Fraunhofer SIT. All rights reserved.
 * See LICENSE file for full terms of use and distribution.
 *
 * Contact: Huajian Liu <liu@sit.fraunhofer.de>
 *
 * @file c40.c
 * @brief C40 encoding and decoding
 */

 #include "jabpro.h"
 #include "c40.h"
 #include "encoder.h"
 #include <stddef.h>
 #include <string.h>
 #include <stdlib.h>
 #include <math.h>
 #include <ctype.h>
 #include <stdio.h>

 /**
 * @brief Encode a string using the C40 scheme
 * @param string the string to be encoded
 * @return the encoded data | NULL: error occurs
*/
 jpro_data* c40_encode(jpro_char* s)
 {
    const jpro_int32 length = strlen( s );
    jpro_int32* c40_values = malloc( sizeof(jpro_int32) * length);
    if ( c40_values == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    jpro_double size = length;

    jpro_data* c40_enocoded_data = malloc( sizeof( jpro_data ) + sizeof ( jpro_byte ) * ceil( size / 3 ) * 2 );
    if ( c40_enocoded_data == NULL )
    {
        error_handler( "Out of memory", OUT_OF_MEMORY );
        return 0;
    }
    c40_enocoded_data->length = ceil( size / 3 ) * 2;        //for each 3 c40 values there are 2 values to be added to data_encoded


    for ( jpro_int32 position = 0; position < length; position++ )    //getting c40 value(s) for every character of the string
    {
       if ( s[position] == '<' )
       {
            c40_values[position] = get_c40_value( ' ' );
       }
       else if ( get_c40_value( s[position] ) != 0 )
       {
            c40_values[position] = get_c40_value( s[position] );
       }
       else
       {
		   //error handled in get_c40_value
           return NULL;
       }
     }

     for ( jpro_int32 position = 0; position < length; position+=3 )
     {
        if( length - position < 3 )                             //Padding
        {
            if( length - position == 2 )
            {
                jpro_uint16 I16 = ( 1600 * c40_values[position]  ) + ( 40 * c40_values[position+1] ) + 0 + 1;
                c40_enocoded_data->data[( position / 3 ) * 2] = I16 / 256;
                c40_enocoded_data->data[( position / 3 ) * 2 + 1] = I16 % 256;
            }
            else if( length - position == 1 )
            {
                c40_enocoded_data->data[( position / 3 ) * 2] = 254;
                c40_enocoded_data->data[( position / 3 ) * 2 + 1] = s[position] + 1;         //ASCII value + 1
            }
        }
        else
        {
            jpro_uint16 I16 = ( 1600 * c40_values[position]  ) + ( 40 * c40_values[position+1] ) + c40_values[position+2] + 1;
            c40_enocoded_data->data[( position / 3 ) * 2] = I16 / 256;
            c40_enocoded_data->data[( position / 3 ) * 2 + 1] = I16 % 256;
        }
     }
     free( c40_values );

	 return c40_enocoded_data;
 }

/**
 * @brief Decode a C40 encoded string
 * @param encoded_data the encoded data to be decoded
 * @return the decoded string | NULL: error occurs
*/
 jpro_char* c40_decode(jpro_data* encoded_data)
 {
     jpro_int32 return_val_len = encoded_data->length * 3/2;
     jpro_char* return_val = malloc( sizeof( jpro_char ) * (return_val_len + 1 ));
     if( return_val == NULL )
     {
         error_handler( "Out of memory", OUT_OF_MEMORY );
         return 0;
     }

     for ( jpro_int32 position = 0; position < encoded_data->length; position+=2 )
     {
        if( encoded_data->data[position] == 0xfe )                             //padding (val, , )
        {
            jpro_uint16 U1 = encoded_data->data[position + 1] - 1;
            snprintf( return_val + (position*3/2), 2, "%c", U1 );
        }
        else
        {
            jpro_uint16 I1 = encoded_data->data[position];
            jpro_uint16 I2 = encoded_data->data[position+1];
            jpro_uint16 V16 = ( I1 * 256 ) + I2;

            jpro_uint16 U1 = ( V16 - 1 ) / 1600;
            jpro_uint16 U2 = ( V16 - ( U1 * 1600 ) - 1 ) / 40;
            jpro_uint16 U3 = V16 - ( U1 * 1600 ) - ( U2 * 40 ) - 1;

            if( U3 == 0 )                                                       //padding (val,val, )
            {
                if( get_char_c40( U1 ) == 0 || get_char_c40( U2 )== 0 )
                {
                    return 0; //error handled in get_char_c40
                }
                snprintf( return_val + (position * 3/2), 3, "%c%c", get_char_c40( U1 ), get_char_c40( U2 ) );
            }
            else
            {
                if( get_char_c40( U1 ) == 0 || get_char_c40( U2 )== 0 || get_char_c40( U3 ) == 0 )
                {
                    return 0; //error handled in get_char_c40
                }
                snprintf( return_val + (position * 3/2), 4, "%c%c%c", get_char_c40( U1 ), get_char_c40( U2 ), get_char_c40( U3 ) );
            }
        }
     }

	 return return_val;
 }

 /**
  *@brief return c40 value for a character
  *@param c  character for c40 value
  *@return the c40 value | 0: ERROR OCCURS
  */
 jpro_int32 get_c40_value( jpro_char c )
 {
     if ( c == ' ' )
     {
         return 3;
     }
     else if( isalpha( c ) &&
              ( c - 51 ) < 40 )
     {
        return ( c - 51 );
     }
     else if( isdigit( c ) )
     {
        return ( c - 44 );
     }
     else
     {
         jpro_char error_msg[256];
         error_handler( cat_strings( error_msg, "Failed to get c40 value for: ", &c, "") , C40_VALUE_UNKNOWN );
         return 0;
     }
 }

/**
 *@brief return character for a c40 value
 *@param i  the c40 value
 *@return the character | 0: ERROR OCCURS
*/
 jpro_char get_char_c40( jpro_uint16 i )
 {
     if( i < 14 && i > 3 )
     {
         return ( i + 44 );
     }
     else if( i == 3 )
     {
         return '<';
     }
     else if( i > 13 && i < 40 )
     {
         return ( i + 51 );
     }
     else
     {
         error_handler( "Failed to get Char for c40 Value" , C40_VALUE_UNKNOWN );
         return 0;
     }
 }
