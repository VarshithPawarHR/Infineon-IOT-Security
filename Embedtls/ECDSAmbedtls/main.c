#include "cyhal.h"
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"

/**************************
* Macros
***************************/


/***************************
* Global Variables
***************************/


/***************************
* Function Prototypes
***************************/


/***************************
* Function Definitions
***************************/
/***************************
* Function Name: print_uint8_data()
****************************
* Summary:
*   Function used to display the data in hexadecimal format
*
* Parameters:
*  uint8_t* data - Pointer to location of data to be printed
*  size_t  len  - length of data to be printed
*
* Return:
*  void
*
***************************/
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

/***************************
 * Function Name: print_mpi_data()
 ****************************
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
 ***************************/
void print_mpi_data(mbedtls_mpi* data)
{
    size_t len = mbedtls_mpi_size(data);
    unsigned char buffer[100] = {0};
    mbedtls_mpi_write_binary(data, buffer, len);
    print_uint8_data(buffer, len);
}

/***************************
 * Function Name: print_ecp_point_data()
 ****************************
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
 **************************/
void print_ecp_point_data(mbedtls_ecp_point* data, mbedtls_ecp_group *grp)
{
    unsigned char buffer[100] = {0};
    size_t buflen = 0; //ECP_KEY_LENGTH

    mbedtls_ecp_point_write_binary(grp, data, MBEDTLS_ECP_PF_UNCOMPRESSED,
            &buflen, buffer, sizeof(buffer));
    print_uint8_data(buffer, buflen);
}

/***************************
* Function Name: main
***************************
* Summary:
* This is the main function for CPU. It generates an ECDSA keypair,
* signs a message, and verifies the signature.
*
* Parameters:
*  void
*
* Return:
*  int
*
***************************/
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
    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX, CY_RETARGET_IO_BAUDRATE);

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

    /* Initialize ECDSA context */
    mbedtls_ecp_keypair keypair;
    mbedtls_mpi r, s;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);



    /* Generate ECDSA keypair */
 mbedtls_ecp_group_load(&keypair.private_grp, MBEDTLS_ECP_DP_SECP256R1); // not needed (required if the things are on different interface)
 mbedtls_ecp_gen_keypair(&keypair.private_grp, &keypair.private_d, &keypair.private_Q, mbedtls_ctr_drbg_random, &random_context);





    /* Hash the message */
    const char *message = "Yokoso Watashi no soul society Ye!";
    uint8_t hash[32];
    mbedtls_sha256((const unsigned char *)message, strlen(message), hash, 0);



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

    /* Free resources */
    mbedtls_ctr_drbg_free(&random_context);
    mbedtls_entropy_free(&entropy_context);
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    for (;;)
    {
    }
}


