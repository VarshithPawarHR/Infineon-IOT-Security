
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

    //declaration of variables
    uint8_t key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t input_buffer[] = {1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6};
    uint8_t output_buffer[16];
    uint8_t rec_buffer[16];

    //context creation
    mbedtls_aes_context aescontext;


    //initialization
    mbedtls_aes_init(&aescontext);

    //key generation
    int keygen =mbedtls_aes_setkey_enc(&aescontext, (const unsigned char *) key,128);

    if(keygen ==0)
    {
    	printf("successful key generation \r\n");

    }
    else{
    	printf("failure ");
    	return 0;
    }

    //encryption

   int cryptsuc = mbedtls_aes_crypt_ecb(&aescontext, MBEDTLS_AES_ENCRYPT, (const unsigned char *) input_buffer ,
    		(unsigned char *) output_buffer);

    if(cryptsuc==0)
    {
    	printf("successful key encryption \r\n");
    }
    else{
    	printf("failure ");
    	    	return 0;
    }

    //print part
    print_uint8_data(output_buffer, sizeof(output_buffer));


    //decryption part starts first with key generation

    int keygen1 =mbedtls_aes_setkey_dec(&aescontext, (const unsigned char *) key,128);

        if(keygen1 ==0)
        {
        	printf("successful key generation\r\n");

        }
        else{
        	printf("failure ");
        	return 0;
        }

        //decryption

        int decryptsuc = mbedtls_aes_crypt_ecb(&aescontext, MBEDTLS_AES_DECRYPT, (const unsigned char *) output_buffer ,
            		(unsigned char *) rec_buffer);

            if(decryptsuc==0)
            {
            	printf("successful key decryption \r\n");
            }
            else{
            	printf("failure ");
            	    	return 0;
            }

            //print part

            print_uint8_data(rec_buffer,sizeof(rec_buffer));

            mbedtls_aes_free(&aescontext);

    for (;;)
    {
    }
}

/* [] END OF FILE */
