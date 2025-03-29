//all the damn import statements

//note this is the complete implementation of DES in ecb mode for cbc mode just use iv vector
//memcpy to copy
//no implementation of DES using cbc will be done hence forth


#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "des.h"


void print_uint8_data(uint8_t* data, size_t len)
{
    char print[10];
    for (uint8_t i=0; i < len; i++)
    {
        if ((i % 16) == 0)
        {
            printf("\r\n");
        }
        sprintf(print,"0x%02X ", *(data+i));
        printf("%s", print);
    }
    printf("\r\n");
}

/*******************************************************************************
 * Function Name: print_mpi_data()
 ********************************************************************************
 * Summary:
 *  Prints the contents of an mbedtls_mpi structure in hexadecimal format.
 *
 * Parameters:
 *  mbedtls_mpi* data: Pointer to the mbedtls_mpi structure to be printed.
 *  size_t  len  - length of data to be printed
 *
 * Return:
 *  void
 *
 *******************************************************************************/
void print_mpi_data(mbedtls_mpi* data)
{
	size_t len = mbedtls_mpi_size(data);
	unsigned char buffer[100] = {0};
    mbedtls_mpi_write_binary(data, buffer, len);
    print_uint8_data(buffer, len);
}

/*******************************************************************************
 * Function Name: print_ecp_point_data()
 ********************************************************************************
 * Summary:
 *  Prints the contents of an mbedtls_ecp_point structure in
 *  uncompressed binary format.
 *
 * Parameters:
 *  mbedtls_ecp_point* data: Pointer to the mbedtls_ecp_point structure to be printed.
 *  mbedtls_ecp_group* grp: Pointer to the mbedtls_ecp_group structure associated
 *  with the point.
 *
 * Return:
 *  void
 *
 ******************************************************************************/
void print_ecp_point_data(mbedtls_ecp_point* data, mbedtls_ecp_group *grp)
{
	unsigned char buffer[100] = {0};
	size_t buflen = 0; //ECP_KEY_LENGTH

    mbedtls_ecp_point_write_binary(grp, data, MBEDTLS_ECP_PF_UNCOMPRESSED,
    		&buflen, buffer, sizeof(buffer));
    print_uint8_data(buffer, buflen);
}

/*******************************************************************************
* Function Name: main
*********************************************************************************
* Summary:
* This is the main function for CPU. It...
*    1.
*    2.
*
* Parameters:
*  void
*
* Return:
*  int
*
*******************************************************************************/
int main(void)
{
    cy_rslt_t result;

    /* Initialize the device and board peripherals */
    result = cybsp_init();

    /* Board init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Enable global interrupts */
    __enable_irq();

    /* Initialize retarget-io to use the debug UART port */
    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX,
    		CY_RETARGET_IO_BAUDRATE);

    /* UART port init failed. Stop program execution */
	if (result != CY_RSLT_SUCCESS)
	{
	   CY_ASSERT(0);
	}

    /* \x1b[2J\x1b[;H - ANSI ESC sequence for clear screen */
    printf("\x1b[2J\x1b[;H");

	//CORE FUNCTIONALITY OF PGM STARTS FROM HERE

    //variable declarations
    uint8_t key[] = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    uint8_t input[] = {1,2,3,4,5,6,7,8};
    uint8_t output[8];
    uint8_t recv[8];

    //context creation
    mbedtls_des_context descontext;

    //initialization
    mbedtls_des_init(&descontext);

    //key creation parity

    int succes =mbedtls_des_setkey_enc(&descontext, (const unsigned char *) key);

    if(succes ==0)
    {
    	printf("key successfully generated \r\n");
    }
    else{
    	printf("Unsuccessful \r\n");
    	return 0;
    }
    //encryption

    int encry = mbedtls_des_crypt_ecb(&descontext,(const unsigned char *) input, (unsigned char * ) output);

    if(encry ==0)
    {

    	printf(" successfully generated \r\n");
    }
    else{
       	printf("Unsuccessful \r\n");
       	return 0;
       }

    //printing
    print_uint8_data(output, sizeof(output));




    //decryption key generation
    int succes1 =mbedtls_des_setkey_dec(&descontext, (const unsigned char *) key);

        if(succes1 ==0)
        {
        	printf("key successfully generated \r\n");
        }
        else{
        	printf("Unsuccessful \r\n");
        	return 0;
        }


    //decryption
        int encry1 = mbedtls_des_crypt_ecb(&descontext,
            		(const unsigned char *) output, (unsigned char * ) recv);

            if(encry1 ==0)
            {

            	printf(" successfully generated \r\n");
            }
            else{
               	printf("Unsuccessful \r\n");
               	return 0;
               }


    //printing
        print_uint8_data(recv, sizeof(recv));




    for (;;)
    {
    }
}

/*
#include <stdio.h>
#include <string.h>
#include "mbedtls/des.h"

void print_data(const char* label, uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("0x%02X ", data[i]);
    }
    printf("\n");
}

int main() {
    uint8_t key[8] = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    uint8_t input[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};  // Example input
    size_t input_len = sizeof(input);
    size_t padded_len = (input_len % 8 == 0) ? input_len : (input_len + (8 - (input_len % 8)));  // Round up to 8-byte blocks

    uint8_t padded_input[padded_len];
    uint8_t output[padded_len];
    uint8_t recv[padded_len];

    mbedtls_des_context descontext;
    mbedtls_des_init(&descontext);

    // 🔹 Copy input and add zero padding
    memset(padded_input, 0, padded_len);
    memcpy(padded_input, input, input_len);

    // 🔹 Set encryption key
    mbedtls_des_setkey_enc(&descontext, key);

    // 🔹 Encrypt each 8-byte block
    for (size_t i = 0; i < padded_len; i += 8) {
        mbedtls_des_crypt_ecb(&descontext, &padded_input[i], &output[i]);
    }

    // 🔹 Set decryption key
    mbedtls_des_setkey_dec(&descontext, key);

    // 🔹 Decrypt each 8-byte block
    for (size_t i = 0; i < padded_len; i += 8) {
        mbedtls_des_crypt_ecb(&descontext, &output[i], &recv[i]);
    }

    // 🔹 Print clean output
    printf("\nENCRYPTED:\n");
    print_data("", output, padded_len);

    printf("\nDECRYPTED (after removing padding):\n");
    print_data("", recv, input_len);  // Only original input length

    mbedtls_des_free(&descontext);
    return 0;
}


 */

