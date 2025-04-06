
//ADD THE DAMN IMPORT STATEMENTS THAT YOU NEED

#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "mbedtls/entropy.h"
#include "ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"



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

	printf("\x1b[2J\x1b[;H");


	//CORE WORKING OF MY PROGRAM

	printf("\x1b[2J\x1b[;H");
	    int ret;
	    const char *message = "Hello, ECDSA!";
	    unsigned char hash[32]; // SHA-256 hash

	    mbedtls_ecp_group grp;
	    mbedtls_mpi d, r, s;
	    mbedtls_ecp_point Q;
	    mbedtls_entropy_context entropy;
	    mbedtls_ctr_drbg_context ctr_drbg;
	    const char *pers = "ecdsa_demo";

	    // Init
	    mbedtls_ecp_group_init(&grp);
	    mbedtls_ecp_point_init(&Q);
	    mbedtls_mpi_init(&d);
	    mbedtls_mpi_init(&r);
	    mbedtls_mpi_init(&s);
	    mbedtls_entropy_init(&entropy);
	    mbedtls_ctr_drbg_init(&ctr_drbg);

	    // Seed RNG
	    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
	                                 (const unsigned char *) pers, strlen(pers));


	    // Load elliptic curve
	    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

	    // Generate keypair
	    mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);

	    // Hash message
	    mbedtls_sha256((const unsigned char *)message, strlen(message), hash, 0);

	    // Sign (deterministic)
	    ret = mbedtls_ecdsa_sign_det_ext(
	        &grp, &r, &s, &d, hash, sizeof(hash),
	        MBEDTLS_MD_SHA256,
	        mbedtls_ctr_drbg_random, &ctr_drbg
	    );

	    if (ret != 0) {
	        printf("Signing failed");
	        return ret;
	    }

	    printf("Signature generated!\n");

	    // Verify
	    ret = mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &Q, &r, &s);

	    if (ret == 0) {
	        printf("Signature verified successfully.\n");
	    } else {
	        printf("Signature verification failed");
	    }

	    // Cleanup
	    mbedtls_ecp_group_free(&grp);
	    mbedtls_ecp_point_free(&Q);
	    mbedtls_mpi_free(&d);
	    mbedtls_mpi_free(&r);
	    mbedtls_mpi_free(&s);
	    mbedtls_ctr_drbg_free(&ctr_drbg);
	    mbedtls_entropy_free(&entropy);






    for (;;)
    {
    }
}
