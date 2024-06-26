#include "jabpro.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

jpro_data* encoded_profile = 0;
jpro_char* output_file = 0;

void print_usage()
{
    printf("\n");
    printf("Usage: to decode an encoded profile\n\n");
	printf("jproDecoder --input <input-file> --output <output-file>\n");
	printf("<input-file>: the path to a ENCODED profile\n");
	printf("<output-file>: the path where the DECODED profile should be saved\n");
	printf("jproDecoder --help: print this help\n" );
}

/**
 *@brief parse command line parameters
 *@return 1: success | 0: failure
*/
jpro_boolean parseParameters( jpro_int32 para_number, jpro_char* para[] )
{
    for( jpro_int32 position = 1; position < para_number; position++ )
    {
        if ( strcmp( para[position], "--input") == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Decoding failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }

            FILE* fp = fopen( para[++position], "rb" );
            if( !fp )
            {
                return 0;
            }

            fseek( fp, 0, SEEK_END );
            jpro_int32 size = ftell( fp );
            fseek( fp, 0, SEEK_SET );

            encoded_profile = malloc( sizeof(jpro_data) + sizeof(jpro_byte) * size );
            encoded_profile->length = size;
            if( encoded_profile == 0 )
            {
                printf("Decoding failed: Out of memory\n");
                return 0;
            }
            fread( encoded_profile->data, sizeof(jpro_byte), size, fp );

            fclose( fp );
        }
        else if ( strcmp( para[position], "--output") == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Decoding failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }
            output_file = malloc(sizeof(jpro_char) * strlen( para[++position] ) );
            if( output_file == 0 )
            {
                printf( "Decoding failed: Out of memory\n" );
                return 0;
            }
            strcpy( output_file, para[position] );
            for (jpro_int32 i = 0; i < strlen(output_file); i++)
            {
                if( output_file[i] == 92 )
                {
                    output_file[i] = '/';
                }
            }
        }
    }
    return 1;
}

int main( int argc, char *argv[] )
{
    if( strcmp( argv[1], "--help" ) == 0 )
    {
        print_usage();
        return 1;
    }

    if( argc < 5 )
    {
        printf( "Decoding failed: invalid amount of arguments \n");
        print_usage();
        return 1;
    }
    if( !parseParameters( argc, argv ) )
    {
        return 1;
    }

    jpro_profile_info* decoded_profile = decode_profile( encoded_profile );
    if( decoded_profile == 0 )
    {
        printf( "Decoding failed: Profile decoding failed\n" );
        return 1;
    }

    jpro_int32 cert_ref_length;
    if( decoded_profile->type == JPRO_VISA ||
        decoded_profile->type == JPRO_RESIDENCE_PERMIT ||
        decoded_profile->type == JPRO_SUPPLEMENTARY_SHEET ||
        decoded_profile->type == JPRO_ADDRESS_STICKER_FOR_ID_CARD ||
        decoded_profile->type == JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT )
    {
        cert_ref_length = 2;
    }
    else if( decoded_profile->type == JPRO_SOCIAL_INSURANCE_CARD || decoded_profile->type == JPRO_ARRIVAL_ATTESTATION_DOCUMENT )
    {
        cert_ref_length = 5;
    }
    else
    {
        return 0;
    }

    FILE* fp = fopen( output_file, "wb" );
    if( !fp )
    {
        printf( "Decoding failed: Opening file failed\n" );
        return 1;
    }
    fwrite( decoded_profile->header.signer_country, 2, 1, fp );
    fwrite( decoded_profile->header.signer_id, 2, 1, fp );
    fwrite( decoded_profile->header.certificate_ref, cert_ref_length, 1, fp );
    fwrite( decoded_profile->header.issuing_country, 3, 1, fp );
    fwrite( decoded_profile->header.issue_date.day, 2, 1, fp );
    fwrite( decoded_profile->header.issue_date.month, 2, 1, fp );
    fwrite( decoded_profile->header.issue_date.year, 4, 1, fp );
    fwrite( decoded_profile->header.signature_date.day, 2, 1, fp );
    fwrite( decoded_profile->header.signature_date.month, 2, 1, fp );
    fwrite( decoded_profile->header.signature_date.year, 4, 1, fp );

    for( jpro_int32 i = 0; i < decoded_profile->feature_cnt; i++ )
    {
        if( decoded_profile->features[i].value_type == JPRO_NUMERIC ||
            decoded_profile->features[i].value_type == JPRO_ALPHANUMERIC ||
            decoded_profile->features[i].value_type == JPRO_BINARY_UTF8 )
        {
            fwrite( decoded_profile->features[i].value_string, strlen(decoded_profile->features[i].value_string), 1, fp );
        }
        else if( decoded_profile->features[i].value_type == JPRO_INTEGER )
        {
            fprintf( fp, "%d", decoded_profile->features[i].value_int );
        }
    }

    fclose( fp );

    free( encoded_profile );
    free(decoded_profile->header.issue_date.year);
    free(decoded_profile->header.issue_date.month);
    free(decoded_profile->header.issue_date.day);
    free(decoded_profile->header.signature_date.year);
    free(decoded_profile->header.signature_date.month);
    free(decoded_profile->header.signature_date.day);
    free(decoded_profile->header.signer_id);
    free(decoded_profile->header.signer_country);
    free(decoded_profile->header.issuing_country);
    free(decoded_profile->header.certificate_ref);
    for( jpro_int32 i = 0; i < decoded_profile->feature_cnt; i++ )
    {
        if( decoded_profile->features[i].value_type == JPRO_ALPHANUMERIC ||
            decoded_profile->features[i].value_type == JPRO_NUMERIC ||
            decoded_profile->features[i].value_type == JPRO_BINARY ||
            decoded_profile->features[i].value_type == JPRO_BINARY_UTF8 )
        {
            free( decoded_profile->features[i].value_string );
        }
    }
    free_profile_info( decoded_profile );
    free(output_file);

    printf("Success\n");

    return 0;
}
