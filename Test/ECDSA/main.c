
#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecp.h"


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


void print_mpi_data(mbedtls_mpi* data)
{
	size_t len = mbedtls_mpi_size(data);
	unsigned char buffer[100] = {0};
    mbedtls_mpi_write_binary(data, buffer, len);
    print_uint8_data(buffer, len);
}


void print_ecp_point_data(mbedtls_ecp_point* data, mbedtls_ecp_group *grp)
{
	unsigned char buffer[100] = {0};
	size_t buflen = 0; //ECP_KEY_LENGTH

    mbedtls_ecp_point_write_binary(grp, data, MBEDTLS_ECP_PF_UNCOMPRESSED,
    		&buflen, buffer, sizeof(buffer));
    print_uint8_data(buffer, buflen);
}

//function needed write here

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

    mbedtls_ctr_drbg_context random_context;
      mbedtls_entropy_context entropy_context;

      /* Initialize the random number generator */
      mbedtls_ctr_drbg_init(&random_context);
      mbedtls_entropy_init(&entropy_context);

      /* Seed the random number generator */
      mbedtls_ctr_drbg_seed(&random_context, mbedtls_entropy_func, &entropy_context, (const unsigned char *)"hello", 5);

	//context creation and all

    mbedtls_ecp_keypair  keypair;
    mbedtls_mpi r,s;

    //initialization
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    //group load
    mbedtls_ecp_group_load(&keypair.private_grp,MBEDTLS_ECP_DP_SECP256R1);

    //keypair gen

    mbedtls_ecp_gen_keypair(&keypair.private_grp, &keypair.private_d, &keypair.private_Q, mbedtls_ctr_drbg_random, &random_context);

    //hash message

    const char * message = "hi there";
    uint8_t hash[32];
    mbedtls_sha256((const unsigned char *)message, strlen(message), hash, 0);

    printf("hash gerated is \r\n");
    print_uint8_data(hash, 32);



    /* Sign the hash */
    result = mbedtls_ecdsa_sign(&keypair.private_grp, &r, &s, &keypair.private_d, hash, sizeof(hash), mbedtls_ctr_drbg_random, &random_context);


    /* Verify the signature */
    int ret = mbedtls_ecdsa_verify(&keypair.private_grp, hash, sizeof(hash), &keypair.private_Q, &r, &s);
    printf("Signature verification result: %d\r\n", ret);

    if (ret == 0)
    {
        printf("Signature verified successfully.\r\n");
    }
    else
    {
        printf("Signature verification failed.\r\n");
    }


    for (;;)
    {
    }
}

/* [] END OF FILE */
