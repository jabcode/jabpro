#include "jabpro.h"
#include "encoder.h"
#include "decoder.h"
#include "c40.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

jpro_profile_info* profile_info = 0;
jpro_data* signature = 0;
jpro_int32 number_features = 0;
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

void free_remaining_data( jpro_profile_info* profile_info, jpro_profile_info* dec_profile, jpro_data* signed_profile, jpro_data* enc_profile_dec, jpro_data* signature_dec , jpro_data* encoded_profile, jpro_data* signature )
{
    free( signed_profile );
    free_header_info_data( dec_profile->header );
    free_feature_values( dec_profile );
    free_profile_info( dec_profile );
    free( enc_profile_dec );
    free( signature_dec );
    free_header_info_data( profile_info->header );
    free_feature_values( profile_info );
    free_profile_info( profile_info );
    free(encoded_profile);
    free(signature);
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
        error_handler( "Out of memory", 0 );
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
        error_handler( "Out of memory", 0 );
        return 0;
    }

    if( type == JPRO_BINARY_UTF8 )
    {
        for( jpro_int32 position = 0; position < length; position++ )
        {
            if( get_random_number( 0, 5 ) == 1 && ( length - position ) > 1 )
            {
                if( get_random_number( 0, 400 ) == 0 )
                {
                    input_string[position] = 0xc3;                                  //2 byte char error
                    input_string[position+1] = get_random_number( 192, 255 );
                    printf( "Error value generated for utf8: '%c %c'\n", input_string[position], input_string[position+1] );
                    position++;
                }
                else
                {
                    input_string[position] = 0xc3;                                  //2 byte char
                    input_string[position+1] = get_random_number( 128, 191 );
                    position++;
                }
            }
            else
            {
                if( get_random_number( 0, 800 ) == 0 )
                {
                    input_string[position] = get_random_number( 192, 255 );
                    printf( "Error value generated for utf8: '%c'\n", input_string[position] );
                }
                else
                {
                    input_string[position] = get_random_number( 65, 122 );
                }
            }
        }
        input_string[length] = '\0';
    }
    else if( type == JPRO_ALPHANUMERIC )
    {
        for( jpro_int32 position = 0; position < length; position++ )
        {
            if( get_random_number( 0, 700 ) == 0 )
            {
                input_string[position] = get_random_number( 33, 126 ); //error input
                printf( "Error value generated for Alphanum: '%c'\n", input_string[position] );
            }
            else
            {
                jpro_int32 num = get_random_number( 0, 37 );
                input_string[position] = alphanum_set[num];
            }
        }
        input_string[length] = '\0';
    }
    else if( type == JPRO_NUMERIC )
    {
        for( jpro_int32 position = 0; position < length; position++ )
        {
            if( get_random_number( 0, 200 ) == 0 )
            {
                input_string[position] = get_random_number( 33, 126 ); //error input
                printf( "Error value generated for numeric: '%c'\n", input_string[position] );
            }
            else
            {
                jpro_int32 num = get_random_number( 0, 10 );
                input_string[position] = num_set[num];
            }
        }
        input_string[length] = '\0';
    }

    return input_string;
}

/**
 *@brief generate a profile with valid inputs
 *@return 1: success | 0: failure
 */
jpro_boolean generate_input_profile( jpro_char* para[] )
{
    /*if( profile_info != NULL )
    {
        free_profile_info( profile_info );
    }*/

    if( strcmp( para[1], "--VISA" ) == 0 )
    {
        profile_info = get_profile_info( JPRO_VISA );
        number_features = profile_info->feature_cnt;
    }
    else if( strcmp( para[1], "--SIC" ) == 0 )
    {
        profile_info = get_profile_info( JPRO_SOCIAL_INSURANCE_CARD );
        number_features = profile_info->feature_cnt;
    }
    else if( strcmp( para[1], "--RP" ) == 0 )
    {
        profile_info = get_profile_info( JPRO_RESIDENCE_PERMIT );
        number_features = profile_info->feature_cnt;
    }
    else if( strcmp( para[1], "--AAD" ) == 0 )
    {
        profile_info = get_profile_info( JPRO_ARRIVAL_ATTESTATION_DOCUMENT );
        number_features = profile_info->feature_cnt;
    }
    else if( strcmp( para[1], "--POR_Sticker" ) == 0 )
    {
        profile_info = get_profile_info( JPRO_PLACE_OF_RESIDENCE_STICKER_FOR_PASSPORT );
        number_features = profile_info->feature_cnt;
    }
    else if( strcmp( para[1], "--ADDR_Sticker" ) == 0 )
    {
        profile_info = get_profile_info( JPRO_ADDRESS_STICKER_FOR_ID_CARD );
        number_features = profile_info->feature_cnt;
    }
    else
    {
        return 0;
    }
    //header
    profile_info->header.signer_id = generate_header_data( 2, "ALPHANUM" );
    profile_info->header.signer_country = generate_header_data( 2, "ALPHANUM" );
    profile_info->header.issuing_country = generate_header_data( 3, "ALPHANUM" );
    if( profile_info->type == JPRO_SOCIAL_INSURANCE_CARD || profile_info->type == JPRO_ARRIVAL_ATTESTATION_DOCUMENT )
    {
        profile_info->header.certificate_ref = generate_header_data( 5, "ALPHANUM" );
    }
    else
    {
        profile_info->header.certificate_ref = generate_header_data( 2, "ALPHANUM" );
    }
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
    //signature
    /*if( signature != NULL )
    {
        free( signature );
    }*/
    signature = malloc( sizeof( jpro_data ) + sizeof(jpro_byte) * 33 );
    if( signature == NULL )
    {
        error_handler( "Out of memory", 0 );
        return 0;
    }
    signature->length = 10;
    for( jpro_int32 position = 0; position < signature->length; position++ )
    {
        signature->data[position] = get_random_number( 0, 255 );
    }

    return 1;
}

/**
 *@brief compares the headers of 2 profiles
 *@param input the input header
 *@param output the decoded output header
 *@return 1: success | 0: failure
 */
jpro_boolean compare_header( jpro_header_info input, jpro_header_info output )
{
    if( strcmp( input.certificate_ref, output.certificate_ref ) != 0 ||
        strcmp( input.issuing_country, output.issuing_country ) != 0 ||
        strcmp( input.signer_country, output.signer_country ) != 0 ||
        strcmp( input.signer_id, output.signer_id ) != 0 ||
        strcmp( input.issue_date.day, output.issue_date.day ) != 0 ||
        strcmp( input.issue_date.month, output.issue_date.month ) != 0 ||
        strcmp( input.issue_date.year, output.issue_date.year ) != 0 ||
        strcmp( input.signature_date.day, output.signature_date.day ) != 0 ||
        strcmp( input.signature_date.month, output.signature_date.month ) != 0 ||
        strcmp( input.signature_date.year, output.signature_date.year ) != 0 )
    {
        return 0;
    }

    return 1;
}

/**
 *@brief compares the features of 2 profiles
 *@param input the input profile
 *@param output the decoded output profile
 *@return 1: success | 0: failure
 */
jpro_boolean compare_features( jpro_profile_info* input, jpro_profile_info* output )
{
    for( jpro_int32 i = 0; i < number_features; i++ )
    {
        if( input->features[i].value_type == JPRO_NUMERIC ||
            input->features[i].value_type == JPRO_ALPHANUMERIC ||
            input->features[i].value_type == JPRO_BINARY_UTF8 )
        {
            if( profile_info->type == JPRO_VISA && i == 0 )
            {
                for( jpro_int32 j = 0; j < 64; j++)
                {
                    if( input->features[i].value_string[j] != output->features[i].value_string[j] )
                    {
                        return 0;
                    }
                }
            }
            else if( strcmp( input->features[i].value_string, output->features[i].value_string ) != 0 )
            {
                return 0;
            }
        }
        else if( input->features[i].value_type == JPRO_INTEGER )
        {
            if( input->features[i].value_int != output->features[i].value_int )
            {
                return 0;
            }
        }
    }
    return 1;
}

int main( int argc, char* argv[] )
{
    if( argc != 2 )
    {
        printf( "Invalid amount of arguments" );
        return 1;
    }
    srand( time(NULL) );

    for( jpro_int32 x = 0; x < 50; x++ )
    {

    if( generate_input_profile( argv ) == 0)
    {
        printf( "Input generation failed" );
        return 1;
    }

    FILE* fp = fopen( "C:\\Users\\biermann\\Documents\\jabpro_intern\\jabpro\\Tests\\Inputs.txt", "w" );
    if( !fp )
    {
        printf( "Opening file failed" );
        free_header_info_data( profile_info->header );
        free_feature_values( profile_info );
        free_profile_info( profile_info );
        free(signature);
        return 1;
    }
    fprintf( fp, "----Header----\n" );
    fprintf( fp, "-Signer id: %s | Signers Country: %s\n", profile_info->header.signer_id, profile_info->header.signer_country );
    fprintf( fp, "-Cert Ref:  %s | Issuing Country: %s\n", profile_info->header.certificate_ref, profile_info->header.issuing_country );
    fprintf( fp, "-Sign Date:  %s.%s.%s\n", profile_info->header.signature_date.day, profile_info->header.signature_date.month, profile_info->header.signature_date.year );
    fprintf( fp, "-Issue Date: %s.%s.%s\n", profile_info->header.issue_date.day, profile_info->header.issue_date.month, profile_info->header.issue_date.year );
    fprintf( fp, "----Features----\n" );
    for( jpro_int32 i = 0; i < number_features; i++ )
    {
        if( profile_info->features[i].value_type == JPRO_ALPHANUMERIC ||
            profile_info->features[i].value_type == JPRO_NUMERIC ||
            profile_info->features[i].value_type == JPRO_BINARY_UTF8 )
        {
            fprintf( fp, "%s: %s\n", profile_info->features[i].name, profile_info->features[i].value_string );
        }
        else if( profile_info->features[i].value_type == JPRO_INTEGER )
        {
            fprintf( fp, "%s: %d\n", profile_info->features[i].name, profile_info->features[i].value_int );
        }
    }
    fclose( fp );

    jpro_data* encoded_profile = encode_profile( profile_info );
    if( encoded_profile == 0 )
    {
        printf("Error: Profile encoding failed\n");
        free_header_info_data( profile_info->header );
        free_feature_values( profile_info );
        free_profile_info( profile_info );
        free(signature);
        return 1;
    }
    jpro_data* signed_profile = append_signature( encoded_profile, signature );
    if( signed_profile == 0 )
    {
        printf("Error: Appending signature failed\n");
        free_header_info_data( profile_info->header );
        free_feature_values( profile_info );
        free_profile_info( profile_info );
        free(encoded_profile);
        free(signature);
        return 1;
    }

	//decoding
	jpro_profile_type decoded_profile_type;
	jpro_header_info* decoded_header_info = decode_header(signed_profile, &decoded_profile_type);
	jpro_profile_info* decoded_profile_info = get_profile_info(decoded_profile_type);
	
    jpro_data* enc_profile_dec = 0;
    jpro_data* signature_dec = 0;

    if( parse_seal( signed_profile, &enc_profile_dec, &signature_dec, decoded_profile_info->crypto->signature_algos[0].size ) == 0 || enc_profile_dec == 0 || signature_dec == 0 )
    {
        printf("Error: Parsing seal failed\n");
        free( signed_profile );
        free_header_info_data( profile_info->header );
        free_feature_values( profile_info );
        free_profile_info( profile_info );
        free(encoded_profile);
        free(signature);
        return 1;
    }

    jpro_profile_info* dec_profile = decode_profile( enc_profile_dec );
    if( dec_profile == 0 )
    {
        printf("\nError: Profile decoding failed\n");
        free( signed_profile );
        free( enc_profile_dec );
        free( signature_dec );
        free_header_info_data( profile_info->header );
        free_feature_values( profile_info );
        free_profile_info( profile_info );
        free(encoded_profile);
        free(signature);
        return 1;
    }

    FILE* fp_out = fopen( "C:\\Users\\biermann\\Documents\\jabpro_intern\\jabpro\\Tests\\Outputs.txt", "w" );
    if( !fp_out )
    {
        printf( "Opening file failed" );
        return 1;
    }
    fprintf( fp_out, "----Header----\n" );
    fprintf( fp_out, "-Signer id: %s | Signers Country: %s\n", dec_profile->header.signer_id, dec_profile->header.signer_country );
    fprintf( fp_out, "-Cert Ref:  %s | Issuing Country: %s\n", dec_profile->header.certificate_ref, dec_profile->header.issuing_country );
    fprintf( fp_out, "-Sign Date:  %s.%s.%s\n", dec_profile->header.signature_date.day, dec_profile->header.signature_date.month, dec_profile->header.signature_date.year );
    fprintf( fp_out, "-Issue Date: %s.%s.%s\n", dec_profile->header.issue_date.day, dec_profile->header.issue_date.month, dec_profile->header.issue_date.year );
    fprintf( fp_out, "----Features----\n" );
    for( jpro_int32 i = 0; i < number_features; i++ )
    {
        if( dec_profile->features[i].value_type == JPRO_ALPHANUMERIC ||
            dec_profile->features[i].value_type == JPRO_NUMERIC ||
            dec_profile->features[i].value_type == JPRO_BINARY_UTF8 )
        {
            fprintf( fp_out, "%s: %s\n", dec_profile->features[i].name, dec_profile->features[i].value_string );
        }
        else if( dec_profile->features[i].value_type == JPRO_INTEGER )
        {
            fprintf( fp_out, "%s: %d\n", dec_profile->features[i].name, dec_profile->features[i].value_int );
        }
    }
    fclose( fp_out );

    if( compare_header( profile_info->header, dec_profile->header ) == 0 )
    {
        printf( "Failure! Different header data" );
        free_remaining_data( profile_info, dec_profile, signed_profile, enc_profile_dec, signature_dec, encoded_profile, signature );
        return 1;
    }
    if( compare_features( profile_info, dec_profile ) == 0 )
    {
        printf( "Failure! Different feature data" );
        free_remaining_data( profile_info, dec_profile, signed_profile, enc_profile_dec, signature_dec, encoded_profile, signature );
        return 1;
    }

    printf( "Success\n" );

    free_remaining_data( profile_info, dec_profile, signed_profile, enc_profile_dec, signature_dec, encoded_profile, signature );

    }

    return 0;
}
