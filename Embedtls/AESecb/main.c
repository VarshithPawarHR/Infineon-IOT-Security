
//import


#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "aes.h"

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

	//Core working of program

    // Sample 128-bit AES key (just for demo)
        uint8_t aes_key[16] = {
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81
        };

        const char *input_string = "12345CDEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        uint8_t *data = (uint8_t *)input_string;
        uint16_t data_len = strlen(input_string);

        // Padding (PKCS#7)
        uint8_t padded_data[100] = {0};
        memcpy(padded_data, data, data_len);

        uint8_t padding_len = 16 - (data_len % 16);
        if (padding_len == 0) padding_len = 16;

        for (int i = data_len; i < data_len + padding_len; i++)
        {
            padded_data[i] = padding_len;
        }

        uint32_t padded_total_len = data_len + padding_len;

        // Encryption
        mbedtls_aes_context aes_enc;
        mbedtls_aes_init(&aes_enc);
        mbedtls_aes_setkey_enc(&aes_enc, aes_key, 128);

        uint8_t encrypted[100] = {0};

        for (size_t i = 0; i < padded_total_len; i += 16)
        {
            mbedtls_aes_crypt_ecb(&aes_enc, MBEDTLS_AES_ENCRYPT, padded_data + i, encrypted + i);
        }

        print_uint8_data(encrypted, padded_total_len);

        // Decryption
        mbedtls_aes_context aes_dec;
        mbedtls_aes_init(&aes_dec);
        mbedtls_aes_setkey_dec(&aes_dec, aes_key, 128);

        uint8_t decrypted[100] = {0};

        for (size_t i = 0; i < padded_total_len; i += 16)
        {
            mbedtls_aes_crypt_ecb(&aes_dec, MBEDTLS_AES_DECRYPT, encrypted + i, decrypted + i);
        }

        // Remove PKCS#7 padding
        uint8_t last_byte = decrypted[padded_total_len - 1];
        if (last_byte <= 16)
        {
        	padded_total_len -=last_byte;
            decrypted[padded_total_len ] = '\0';
        }


        printf("\r\nDecrypted string: %s\r\n", decrypted);

        mbedtls_aes_free(&aes_enc);
        mbedtls_aes_free(&aes_dec);

        return 0;
    for (;;)
    {
    }
}

/* [] END OF FILE */
