#include "jabpro.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

jpro_profile_info* profile_info = 0;
jpro_int32 number_features = 0;
jpro_char* file_name = 0;
static jpro_char* year_set[10] = { "2015", "2016", "2017", "2018", "2019", "2020", "2021", "2022", "2023", "2024"};
static jpro_char* day_set[30] = { "01", "02", "03", "04", "05", "06", "07", "08", "09", "10",
                                  "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
                                  "21", "22", "23", "24", "25", "26", "27", "28", "29", "30" };
static const jpro_char num_set[10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
static const jpro_char alphanum_set[37] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                                            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                                            'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                                            'U', 'V', 'W', 'X', 'Y', 'Z', '<' };
/**
 *@brief print usage for command line
*/
void print_usage()
{
    printf("\n");
    printf("Usage:\n\n");
	printf("jproEncoder --ProfileType <profile-type> --input-file <input-file> --output <output-file>\n");
	printf("jproEncoder --ProfileType <profile-type> --random <inputs-path> --output <output-file>\n" );
	printf("<profile-type>: accepted profile types:\n -->VISA: Visa document\n -->RP: Residence permit\n -->AAD: Arrival attestation document\n" );
	printf(" -->SIC: Social insurance card\n -->ADDR_Sticker: Address sticker for id card\n -->POR_Sticker: Place of residence sticker\n" );
	printf("--random: generate random inputs for profile\n" );
	printf("<inputs-path>: path to the randomly created input data\n" );
	printf("jproEncoder --ProfileType <profile-type> --header <input-header> --features <feature1> ... <featureN> --output <output-file> \n");
	printf("<input-header> of form: <signer-country> <signer-id> <cert-ref> <issuing-country> <issue-date> <sign-date>\n");
	printf("jproEncoder --help: print this help\n ");
}

/**
 *@brief generate a random number
 *@param min_value the min value that can be created
 *@param max_value the max value that can be created
 *@return the created number
*/
jpro_int32 get_random_number( jpro_int32 min_value, jpro_int32 max_value )
{
    jpro_int32 number = 0;
    if( min_value == max_value )
    {
        number = max_value;
    }
    else
    {
        number = rand() % (max_value - min_value) + min_value;
    }
    return number;
}

/**
 *@brief create a random header string
 *@param length the length of the string
 *@param type the value_type of the string
 *@return the created string | NULL: error occurs
 */
jpro_char* generate_header_data( jpro_int32 length, jpro_char* type )
{
    jpro_char* header_data = malloc( sizeof( jpro_char ) * ( length + 1 ) );
    if( header_data == NULL )
    {
        return 0;
    }

    if( strcmp( type, "ALPHANUM" ) == 0 )
    {
        for( jpro_int32 position = 0; position < length; position++ )
        {
            jpro_int32 num = get_random_number( 0, 37 );
            header_data[position] = alphanum_set[ num ];
        }
        header_data[length] = '\0';
    }
    else if( strcmp( type, "NUMBER" ) == 0 )
    {
        for( jpro_int32 position = 0; position < length; position++ )
        {
            jpro_int32 num = get_random_number( 0, 10 );
            header_data[position] = alphanum_set[ num ];
        }
        header_data[length] = '\0';
    }
    else if( strcmp( type, "DAY" ) == 0)
    {
        jpro_int32 num = get_random_number( 0, 28 );
        memcpy( header_data, day_set[num], length );
        header_data[length] = '\0';
    }
    else if( strcmp( type, "MONTH" ) == 0 )
    {
        jpro_int32 num = get_random_number( 0, 11 );
        memcpy( header_data, day_set[num], length );
        header_data[length] = '\0';
    }
    else if( strcmp( type, "YEAR" ) == 0 )
    {
        jpro_int32 num = get_random_number( 0, 10 );
        memcpy( header_data, year_set[num], length );
        header_data[length] = '\0';
    }
    else if( strcmp( type, "COUNTRY" ) == 0 )
    {
        for( jpro_int32 position = 0; position < length; position++ )
        {
            jpro_int32 num = get_random_number( 10, 36 );
            header_data[position] = alphanum_set[ num ];
        }
        header_data[length] = '\0';
    }

    return header_data;
}

/**
 *@brief create a random string feature
 *@param length the length of the string
 *@param type the value_type of the string
 *@return the created string | NULL: error occurs
 */
jpro_char* get_random_feature( jpro_int32 length, jpro_feature_type type )
{
    jpro_char* input_string = malloc( sizeof( jpro_char ) * ( length + 1 ) );
    if( input_string == NULL )
    {
        return 0;
    }

    if( type == JPRO_BINARY_UTF8 )
    {
        for( jpro_int32 position = 0; position < length; position++ )
        {
            if( get_random_number( 0, 5 ) == 1 && ( length - position ) > 1 )
            {
                input_string[position] = 0xc3;                                  //2 byte char
                input_string[position+1] = get_random_number( 128, 191 );
                position++;
            }
            else
            {
                input_string[position] = get_random_number( 65, 122 );
            }
        }
        input_string[length] = '\0';
    }
    else if( type == JPRO_ALPHANUMERIC )
    {
        for( jpro_int32 position = 0; position < length; position++ )
        {
            jpro_int32 num = get_random_number( 0, 37 );
            input_string[position] = alphanum_set[num];
        }
        input_string[length] = '\0';
    }
    else if( type == JPRO_NUMERIC )
    {
        for( jpro_int32 position = 0; position < length; position++ )
        {
            jpro_int32 num = get_random_number( 0, 10 );
            input_string[position] = num_set[num];
        }
        input_string[length] = '\0';
    }

    return input_string;
}

/**
 *@brief generate a profile with valid inputs
 *@return 1: success | 0: failure
 */
jpro_boolean generate_input_profile( jpro_char* inputs_path )
{
    jpro_int32 cert_ref_length;
    if( profile_info->type == JPRO_VISA ||
        profile_info->type == JPRO_RESIDENCE_PERMIT ||
        profile_info->type == JPRO_SUPPLEMENTARY_SHEET ||
        profile_info->type == JPRO_ADDRESS_STICKER_FOR_ID_CARD ||
        profile_info->type == JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT )
    {
        cert_ref_length = 2;
    }
    else if( profile_info->type == JPRO_SOCIAL_INSURANCE_CARD || profile_info->type == JPRO_ARRIVAL_ATTESTATION_DOCUMENT )
    {
        cert_ref_length = 5;
    }
    else
    {
        return 0;
    }

    //header
    profile_info->header.signer_id = generate_header_data( 2, "ALPHANUM" );
    profile_info->header.signer_country = generate_header_data( 2, "COUNTRY" );
    profile_info->header.issuing_country = generate_header_data( 3, "COUNTRY" );
    profile_info->header.certificate_ref = generate_header_data( cert_ref_length, "ALPHANUM" );
    profile_info->header.signature_date.day = generate_header_data( 2, "DAY" );
    profile_info->header.signature_date.month = generate_header_data( 2, "MONTH" );
    profile_info->header.signature_date.year = generate_header_data( 4, "YEAR" );
    profile_info->header.issue_date.day = generate_header_data( 2, "DAY" );
    profile_info->header.issue_date.month = generate_header_data( 2, "MONTH" );
    profile_info->header.issue_date.year = generate_header_data( 4, "YEAR" );

    //features
    for( jpro_int32 i = 0; i < number_features; i++ )
    {
        if( profile_info->features[i].value_type == JPRO_NUMERIC ||
            profile_info->features[i].value_type == JPRO_ALPHANUMERIC ||
            profile_info->features[i].value_type == JPRO_BINARY_UTF8 )
        {
            jpro_int32 len = get_random_number( profile_info->features[i].min_length, profile_info->features[i].max_length );
            profile_info->features[i].value_string = get_random_feature( len, profile_info->features[i].value_type );
        }
        else if( profile_info->features[i].value_type == JPRO_INTEGER )
        {
            profile_info->features[i].value_int = get_random_number( 0, 255 );
        }
    }
    for (jpro_int32 i = 0; i < strlen(inputs_path); i++)
    {
        if( inputs_path[i] == 92 )
        {
            inputs_path[i] = '/';
        }
    }

    FILE* fp_i = fopen( inputs_path, "wb" );              //write inputs to file
    if( !fp_i )
    {
        printf( "Encoding failed: Opening file failed\n" );
        return 1;
    }
    fwrite( profile_info->header.signer_country, 2, 1, fp_i );
    fwrite( profile_info->header.signer_id, 2, 1, fp_i );
    fwrite( profile_info->header.certificate_ref, cert_ref_length, 1, fp_i );
    fwrite( profile_info->header.issuing_country, 3, 1, fp_i );
    fwrite( profile_info->header.issue_date.day, 2, 1, fp_i );
    fwrite( profile_info->header.issue_date.month, 2, 1, fp_i );
    fwrite( profile_info->header.issue_date.year, 4, 1, fp_i );
    fwrite( profile_info->header.signature_date.day, 2, 1, fp_i );
    fwrite( profile_info->header.signature_date.month, 2, 1, fp_i );
    fwrite( profile_info->header.signature_date.year, 4, 1, fp_i );

    for( jpro_int32 i = 0; i < profile_info->feature_cnt; i++ )
    {
        if( profile_info->features[i].value_type == JPRO_NUMERIC ||
            profile_info->features[i].value_type == JPRO_ALPHANUMERIC ||
            profile_info->features[i].value_type == JPRO_BINARY_UTF8 )
        {
            fwrite( profile_info->features[i].value_string, strlen(profile_info->features[i].value_string), 1, fp_i );
        }
        else if( profile_info->features[i].value_type == JPRO_INTEGER )
        {
            fprintf( fp_i, "%d", profile_info->features[i].value_int );
        }
    }
    fclose( fp_i );

    return 1;
}

/**
 *@brief parse command line parameters
 *@return 1: success | 0: failure
*/
jpro_boolean parseParameters( jpro_int32 para_number, jpro_char* para[] )
{
    for( jpro_int32 position = 1; position < para_number; position++ )
    {
        if( strcmp( para[position], "--ProfileType") == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Value for '%s' missing.\n", para[position] );
                return 0;
            }
            if( profile_info )
            {
                free_profile_info(profile_info);
            }
            jpro_profile_type type;
            if( strcmp( para[position+1], "VISA" ) == 0 )
            {
                printf( "Input: Visa Document\n");
                type = JPRO_VISA;
            }
            else if ( strcmp( para[position+1], "AAD" )== 0 )
            {
                printf( "Input: Arrival Attestation Document\n");
                type = JPRO_ARRIVAL_ATTESTATION_DOCUMENT;
            }
            else if ( strcmp( para[position+1], "SIC" ) == 0)
            {
                printf( "Input: Social incurance card\n");
                type = JPRO_SOCIAL_INSURANCE_CARD;
            }
            else if ( strcmp( para[position+1], "RP" ) == 0 )
            {
                printf( "Input: Residence permit Document\n");
                type = JPRO_RESIDENCE_PERMIT;
            }
            else if ( strcmp( para[position+1], "RP_SUPP_SHEET" ) == 0 )
            {
                printf( "Input: Supplementary sheet for residence permit\n" );
                type = JPRO_SUPPLEMENTARY_SHEET;
            }
            else if ( strcmp( para[position+1], "POR_Sticker" ) == 0 )
            {
                printf( "Input: Place of residence sticker Document\n");
                type = JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT;
            }
            else if ( strcmp( para[position+1], "ADDR_Sticker" ) == 0 )
            {
                printf( "Input: Address sticker Document\n");
                type = JPRO_ADDRESS_STICKER_FOR_ID_CARD;
            }
            profile_info = get_profile_info( type );
            number_features = profile_info->feature_cnt;

            position++;
        }
        else if ( strcmp( para[position], "--input-file") == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Encoding failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }

            FILE* fp = fopen( para[++position], "r" );
            if( !fp )
            {
                printf( "Encoding failed: Reading file failed\n" );
                return 0;
            }
            fseek( fp, 0, SEEK_END );
            jpro_int32 size_fp = ftell( fp );
            fseek( fp, 0, SEEK_SET );

            jpro_char** buffer_header = malloc( 10 * sizeof( char * ) );                                                    //Header
            if( buffer_header == 0 )
            {
                return 0;
            }
            jpro_int32 c;
            for ( jpro_int32 i = 0; i < 10; i++ )
            {
                buffer_header[i] = ( jpro_char * )malloc( sizeof( jpro_char ) * 6);
                jpro_int32 loop = 0;
                while( (c = getc( fp )) != ' ' && c != EOF )
                {
                    buffer_header[i][loop] = c;
                    buffer_header[i][loop+1] = '\0';
                    loop++;
                }
            }
            profile_info->header.signer_country = buffer_header[0];
            profile_info->header.signer_id = buffer_header[1];
            profile_info->header.certificate_ref = buffer_header[2];
            profile_info->header.issuing_country = buffer_header[3];
            profile_info->header.issue_date.day = buffer_header[4];
            profile_info->header.issue_date.month = buffer_header[5];
            profile_info->header.issue_date.year = buffer_header[6];
            profile_info->header.signature_date.day = buffer_header[7];
            profile_info->header.signature_date.month = buffer_header[8];
            profile_info->header.signature_date.year = buffer_header[9];

            free( buffer_header );

            jpro_char **buffer_features = malloc( number_features * sizeof( char * ) );;
            for( jpro_int32 i = 0; i < number_features; i++ )                                                                  //features
            {
                if( profile_info->features[i].value_type == JPRO_ALPHANUMERIC ||
                    profile_info->features[i].value_type == JPRO_NUMERIC ||
                    profile_info->features[i].value_type == JPRO_BINARY ||
                    profile_info->features[i].value_type == JPRO_BINARY_UTF8 )
                {
                    buffer_features[i] = ( jpro_char* )malloc( sizeof( jpro_char ) * 255 );
                    jpro_int32 loop = 0;
                    while( (c = getc( fp )) != ' ' && c != EOF )
                    {
                        buffer_features[i][loop] = c;
                        buffer_features[i][loop+1] = '\0';
                        loop++;
                    }
                    profile_info->features[i].value_string = buffer_features[i];
                }
                else if( profile_info->features[i].value_type == JPRO_INTEGER )
                {
                    fscanf( fp, "%d", &profile_info->features[i].value_int );
                    fseek( fp, 1, SEEK_CUR );
                }
            }

            free( buffer_features );
            fclose( fp );
        }
        else if ( strcmp( para[position], "--header") == 0 )                            //--header cert_ref cntry_id dd mm yyyy dd mm yyyy
        {                                                                               //                           issue date/ sign date
            jpro_header_info header_info;
            for( jpro_int32 i = 0; i < 8; i++ )
            {
                if( position + i + 1 > para_number - 1 )
                {
                    printf( "Encoding failed: Not enough values for '%s'\n", para[position] );
                    return 0;
                }
            }
            jpro_date issue_date, sign_date;
            issue_date.day = para[position + 5];
            issue_date.month = para[position + 6];
            issue_date.year = para[position + 7];
            sign_date.day = para[position + 8 ];
            sign_date.month = para[position + 9 ];
            sign_date.year = para[position + 10 ];

            header_info.signer_country = para[position + 1];
            header_info.signer_id = para[position + 2];
            header_info.certificate_ref = para[position + 3];
            header_info.issuing_country = para[position + 4];
            header_info.issue_date = issue_date;
            header_info.signature_date = sign_date;

            profile_info->header = header_info;

            position+=10;
        }
        else if ( strcmp( para[position], "--features") == 0 )
        {
            for( jpro_int32 i = 0; i < number_features; i++ )
            {
                if( position + i + 1 > para_number - 1 )
                {
                    printf( "Encoding failed: Not enough values for '%s'\n", para[position] );
                    return 0;
                }
            }
            position++;
            for( jpro_int32 i = 0; i < number_features; i++ )
            {
                if( profile_info->features[i].value_type == JPRO_ALPHANUMERIC ||
                    profile_info->features[i].value_type == JPRO_NUMERIC ||
                    profile_info->features[i].value_type == JPRO_BINARY ||
                    profile_info->features[i].value_type == JPRO_BINARY_UTF8 )
                {
                    profile_info->features[i].value_string = para[position + i];
                }
                else if( profile_info->features[i].value_type == JPRO_INTEGER )
                {
                    profile_info->features[i].value_int = atoi( para[position + i] );
                }
                else
                {
                    printf( "Encoding failed: Unknown profile Type\n");
                    return 0;
                }
            }
            position+=( number_features - 1 );
        }
        else if( strcmp( para[position], "--random" ) == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Encoding failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }

            if( !generate_input_profile( para[++position]) )
            {
                printf("Encoding failed: Generating input failed\n" );
                return 0;
            }
        }
        else if (strcmp( para[position], "--output" ) == 0 )
        {
            if( position + 1 > para_number - 1 )
            {
                printf( "Encoding failed: Not enough values for '%s'\n", para[position] );
                return 0;
            }
            file_name = malloc( sizeof(jpro_char) * strlen( para[++position] ));
            if (file_name == 0)
            {
                printf( "Encoding failed: Out of memory\n" );
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
        printf( "Encoding failed: invalid amount of arguments\n");
        print_usage();
        return 1;
    }
    srand( time(NULL) );
    if( !parseParameters( argc, argv ) )
    {
        printf( "Encoding failed: Parsing parameters failed\n" );
        return 1;
    }
    jpro_data* encoded_profile = encode_profile( profile_info );
    if( encoded_profile == 0 )
    {
        printf( "Encoding failed: Profile encoding failed\n");
        return 1;
    }

    FILE* output_file = fopen( file_name, "wb" );
    if( !output_file )
    {
        printf( "Encoding failed: Opening file failed\n" );
        return 1;
    }
    fwrite( encoded_profile->data, encoded_profile->length, 1, output_file );
    fclose( output_file );

    free(profile_info->header.issue_date.year);
    free(profile_info->header.issue_date.month);
    free(profile_info->header.issue_date.day);
    free(profile_info->header.signature_date.year);
    free(profile_info->header.signature_date.month);
    free(profile_info->header.signature_date.day);
    free(profile_info->header.signer_id);
    free(profile_info->header.signer_country);
    free(profile_info->header.issuing_country);
    free(profile_info->header.certificate_ref);
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
    free_profile_info( profile_info );
    free(encoded_profile);
    free(file_name);

    return 0;
}
