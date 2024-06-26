#include "jabpro.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

jpro_data* encoded_profile = 0;
jpro_data* signature = 0;
jpro_char* file_name = 0;

/**
 *@brief print usage
 */
void print_usage()
{
    printf("\n");
    printf("Usage: to append signature to an encoded profile\n\n");
	printf("jproSigner --profile <profile-file> --signature <signature-file> --output <output-file>\n");
	printf("->profile-file: the path to a ENCODED profile\n");
	printf("->signature-file: the path to a SIGNATURE\n");
	printf("->output-file: the path where the SIGNED profile should be saved\n");
	printf("jproSigner --help: print this help\n );
}

/**
 *@brief parse command line parameters
 *@return 1: success | 0: failure
*/
jpro_boolean parseParameters( jpro_int32 para_number, jpro_char* para[] )
{
    for( jpro_int32 position = 1; position < para_number; position++ )
    {
        if ( strcmp( para[position], "--profile") == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Signing failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }

            FILE* fp = fopen( para[++position], "rb" );
            if( !fp )
            {
                return 0;
            }

            fseek( fp, 0, SEEK_END );
            jpro_int32 size_encoded_profile = ftell( fp );
            fseek( fp, 0, SEEK_SET );

            //read the binary values for encoded profile
            encoded_profile = malloc( sizeof(jpro_data) + sizeof(jpro_byte) * size_encoded_profile );
            encoded_profile->length = size_encoded_profile;
            if( encoded_profile == 0 )
            {
                printf("Signing failed: Out of memory\n");
                return 0;
            }
            fread( encoded_profile->data, sizeof(jpro_byte), size_encoded_profile, fp );

            fclose( fp );
        }
        else if ( strcmp( para[position], "--signature") == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Signing failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }

            FILE* fp = fopen( para[++position], "rb" );
            if( !fp )
            {
                printf( "Signing failed: Opening file failed\n" );
                return 0;
            }
            fseek( fp, 0, SEEK_END );
            jpro_int32 size_signature = ftell( fp );
            fseek( fp, 0, SEEK_SET );

            signature = malloc( sizeof(jpro_data) + sizeof(jpro_byte) * size_signature );
            signature->length = size_signature;
            if( signature == 0 )
            {
                printf("Signing failed: Out of memory\n");
                return 0;
            }
            fread( signature->data, sizeof(jpro_byte), size_signature, fp );

            fclose( fp );
        }
        else if ( strcmp( para[position], "--output") == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Signing failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }
            file_name = malloc( sizeof( jpro_char ) * strlen( para[++position] ) );
            if( file_name == 0 )
            {
                printf( "Signing failed: Out of memory\n" );
                return 0;
            }
            strcpy( file_name, para[position] );
            for (jpro_int32 i = 0; i < strlen(file_name); i++)
            {
                if( file_name[i] == 92 )
                {
                    file_name[i] = '/';
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

    if( argc < 7 )
    {
        printf( "Signing failed: invalid amount of arguments\n");
        print_usage();
        return 1;
    }
    if( !parseParameters( argc, argv ) )
    {
        return 1;
    }
    jpro_data* signed_profile = append_signature( encoded_profile, signature );
    if( signed_profile == 0 )
    {
        printf( "Signing failed: Appending signature failed\n" );
        return 1;
    }
    FILE* fp = fopen( file_name, "wb" );
    if( !fp )
    {
        printf( "Signing failed: Opening file failed\n" );
        return 1;
    }
    fwrite( signed_profile->data, signed_profile->length, 1, fp );
    fclose( fp );

    free( signature );
    free( encoded_profile );
    free(file_name);

    return 0;
}
