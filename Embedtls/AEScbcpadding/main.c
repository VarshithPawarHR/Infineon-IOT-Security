#if defined (CY_USING_HAL)
#include "cyhal.h"
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "ctr_drbg.h"
#include "aes.h"
#include "entropy.h"
#endif



/* Helper function to print data in hex format */
void print_uint8_data(uint8_t* data, size_t len)
{
    char print[10];
    for (uint8_t i = 0; i < len; i++)
    {
        if ((i % 16) == 0)
        {
            printf("\r\n");
        }
        sprintf(print, "0x%02X ", *(data + i));
        printf("%s", print);
    }
    printf("\r\n");
}

/*******************************************************************************
* Function Name: main
********************************************************************************/
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

    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Clear terminal */
    printf("\x1b[2J\x1b[;H");

    printf("Starting AES Encryption with mbedTLS...\r\n");


    mbedtls_aes_context aescontext;


    mbedtls_aes_init(&aescontext);

	//context creation
	mbedtls_entropy_context entropycontext;
	mbedtls_ctr_drbg_context drbgcontext;

	//initialization
	mbedtls_entropy_init(&entropycontext);
	 mbedtls_ctr_drbg_init(&drbgcontext);


	 //seeding
	  mbedtls_ctr_drbg_seed(&drbgcontext,  mbedtls_entropy_func ,&entropycontext,(const unsigned char *)"hello", 5);



    // Generate a random AES key (128-bit)
    uint8_t key[16] = {0};
    int keyflag = mbedtls_ctr_drbg_random(&drbgcontext, key, sizeof(key));

    if (keyflag != 0)
    {
        printf("Failure in generating random AES key: -0x%04X\r\n", -keyflag);
        return -1;
    }



    // Set AES encryption key
    int keygencheck = mbedtls_aes_setkey_enc(&aescontext, key, 128);
    if (keygencheck != 0)
    {
        printf("Failure in setting AES encryption key: -0x%04X\r\n", -keygencheck);
        return -1;
    }

    // Data to encrypt
    const char *inputstring = "hello there what are you doing?";
    uint8_t *data = (uint8_t *)inputstring;
    uint16_t datalength = strlen(inputstring);

    // Padding (PKCS#7)
    uint8_t paddingdata[100] = {0};
    uint8_t paddinglen = 16 - (datalength % 16);
    if (paddinglen == 0)
    {
        paddinglen = 16;
    }

    memcpy(paddingdata, data, datalength);
    for (int i = datalength; i < datalength + paddinglen; i++)
    {
        paddingdata[i] = paddinglen;
    }

    uint8_t totalpaddinglen = datalength + paddinglen;

    // Initialization Vector (IV)
    uint8_t iv[16] = {1,2,3,4,5,6,7,8,9,10,1,2,3,4,5,6};
    uint8_t ivcpy[16] = {0};
    memcpy(ivcpy, iv, sizeof(iv));

    // Buffer for encrypted output
    uint8_t encrypt[100] = {0};

    // AES-CBC Encryption
    for (int i = 0; i < totalpaddinglen; i += 16)
    {
        mbedtls_aes_crypt_cbc(&aescontext, MBEDTLS_AES_ENCRYPT, 16, iv,
                              paddingdata + i, encrypt + i);
    }

    printf("\r\nEncrypted Data:");
    print_uint8_data(encrypt, totalpaddinglen);

    //decryption

    int keygenchecki = mbedtls_aes_setkey_dec(&aescontext, key, 128);
        if (keygenchecki != 0)
        {
            printf("Failure in setting AES encryption key: -0x%04X\r\n", -keygencheck);
            return -1;
        }

      uint8_t  decrypt[100] ={0};


        // AES-CBC Encryption
            for (int i = 0; i < totalpaddinglen; i += 16)
            {
                mbedtls_aes_crypt_cbc(&aescontext,MBEDTLS_AES_DECRYPT, 16, ivcpy,
                                      encrypt + i, decrypt + i);
            }

            //unpadding

            uint8_t lastbyte = decrypt[totalpaddinglen-1];
            if(lastbyte<=16)
            {
            	totalpaddinglen -= lastbyte;
            	decrypt[totalpaddinglen] = '\0';
            }


            printf("decrypted data : %s \r\n",decrypt);



    for (;;)
    {
        // Infinite loop
    }
}

/* [] END OF FILE */
