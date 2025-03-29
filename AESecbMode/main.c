
//Put the DAMN necessary imports here

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

	//Core logic of program

    //variable declaration
    uint8_t key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t iv[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t input_buff[] = {1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6};
    uint8_t output_buff[16];

    uint8_t iv2[16];

    memcpy(iv2,iv,16);

    uint8_t recv_buff[16];





    //context creation
    mbedtls_aes_context aescontext;

    //initialization
    mbedtls_aes_init(&aescontext);

    //set key
    int flag = mbedtls_aes_setkey_enc(&aescontext,key, 128);

    if(flag ==0)
    {
    	printf("key generated successfully \r\n");

    }
    else{
    	printf("encryption  key generation failure \r\n");
    	return 0;
    }

    //encryption

    int flag1 = mbedtls_aes_crypt_cbc(&aescontext, MBEDTLS_AES_ENCRYPT,16,iv,
    		(const unsigned char *) input_buff , (unsigned char *) output_buff);

    if(flag1 ==0)
    {
    	printf("successfull encryption \r\n");
    }
    else{
    	printf("unsuccessfull in encryption \r\n");
    	return 0;
    }

    //print it

    print_uint8_data(output_buff, sizeof(output_buff));

    //decryption part starts

    //set key for decryption

    int flag2 = mbedtls_aes_setkey_dec(&aescontext,key, 128);

    if(flag2 ==0)
        {
        	printf("key generated successfully \r\n");

        }
        else{
        	printf("encryption  key generation failure \r\n");
        	return 0;
        }

    //decryption

    int flag3 = mbedtls_aes_crypt_cbc(&aescontext, MBEDTLS_AES_DECRYPT,16,iv2,
       		(const unsigned char *) output_buff , (unsigned char *) recv_buff);


    if(flag3 ==0)
    {
    	printf("successfull decryption \r\n");
    }
    else{
    	printf("unsuccessfull in decrryption \r\n");
    	return 0;
    }



    //printing

    //print it

        print_uint8_data(recv_buff, sizeof(recv_buff));

        //free the context
        mbedtls_aes_free(&aescontext);







    for (;;)
    {
    }
}

/* [] END OF FILE */
