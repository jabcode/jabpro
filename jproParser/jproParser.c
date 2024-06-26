#include "jabpro.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

jpro_data* signed_profile = 0;
jpro_char* profile_file = 0;
jpro_char* signature_file = 0;
jpro_int32 signature_length = 0;

void print_usage()
{
    printf("\n");
    printf("Usage: To split encoded profile and signature\n\n");
	printf("jproParser --input <input-file> --length <signature_length> --profile <profile-file> --signature <signature-file>\n");
	printf("->input-file: the path to a SIGNED profile\n");
	printf("->profile-file: the path where the ENCODED profile should be saved\n");
	printf("->signature-file: the path where the SIGNATURE should be saved\n");
	printf("jproParser --help: print this help\n" );
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
                printf( "Parsing failed: Not enough values for '%s'\n", para[position] );
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

            signed_profile = malloc( sizeof(jpro_data) + sizeof(jpro_byte) * (size + 1) );
            signed_profile->length = size;
            if( signed_profile == 0 )
            {
                printf("Out of memory\n");
                return 0;
            }
            fread( signed_profile->data, sizeof(jpro_byte), size, fp );
            signed_profile->data[size] = '\n';

            fclose( fp );
        }
        else if( strcmp( para[position], "--length" ) == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Parsing failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }

            signature_length = atoi( para[++position] );
        }
        else if ( strcmp( para[position], "--profile") == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Parsing failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }
            profile_file = malloc( sizeof( jpro_char ) * strlen( para[++position] ) );
            if( profile_file == 0 )
            {
                printf( "Parsing failed: Out of memory\n" );
                return 0;
            }
            strcpy( profile_file, para[position] );
            for (jpro_int32 i = 0; i < strlen(profile_file); i++)
            {
                if( profile_file[i] == 92 )
                {
                    profile_file[i] = '/';
                }
            }
        }
        else if ( strcmp( para[position], "--signature") == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Parsing failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }
            signature_file = malloc( sizeof( jpro_char ) * strlen( para[++position] ) );
            if( signature_file == 0 )
            {
                printf( "Parsing failed: Out of memory\n" );
                return 0;
            }
            strcpy( signature_file, para[position] );
            for (jpro_int32 i = 0; i < strlen(signature_file); i++)
            {
                if( signature_file[i] == 92 )
                {
                    signature_file[i] = '/';
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

    if( argc < 9 )
    {
        printf( "Parsing failed: invalid amount of arguments\n");
        print_usage();
        return 1;
    }
    if( !parseParameters( argc, argv ) )
    {
        return 1;
    }

    jpro_data* encoded_profile = 0;
    jpro_data* signature = 0;
    if ( parse_seal( signed_profile, &encoded_profile, &signature, signature_length ) == 0)
    {
        printf( "Parsing failed: Parsing seal failed.\n");
        return 1;
    }

    FILE* fp = fopen( profile_file, "wb" );
    if( !fp )
    {
        printf( "Parsing failed: Opening file failed\n" );
        return 1;
    }
    fwrite( encoded_profile->data, encoded_profile->length, 1, fp );

    fclose( fp );

    FILE* fp2 = fopen( signature_file, "wb" );
    if( !fp2 )
    {
        printf( "Parsing failed: Opening file failed\n" );
        return 1;
    }
    fwrite( signature->data, signature->length, 1, fp2 );

    fclose( fp2 );

    free( signature );
    free( encoded_profile );
    free( signed_profile );
    free(signature_file);
    free(profile_file);

    return 0;
}
