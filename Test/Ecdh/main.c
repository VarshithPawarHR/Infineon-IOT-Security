
#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "ctr_drbg.h"
#include "entropy.h"
#include "ecdh.h"


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

//Functions to write

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


    //CORE FUNCTION HERE
    //random number generation

    mbedtls_ctr_drbg_context drbgcontext;
    mbedtls_entropy_context entropycontext;

    //initialization
    mbedtls_ctr_drbg_init(&drbgcontext);
    mbedtls_entropy_init(&entropycontext);

    //seeding
    mbedtls_ctr_drbg_seed(&drbgcontext,
    		mbedtls_entropy_func,
    		&entropycontext, (const unsigned char *)"hello",5);

    //ECDH initialization

    mbedtls_ecdh_context alicecontext;
    mbedtls_ecdh_init(&alicecontext);
    mbedtls_ecdh_context bobcontext;
        mbedtls_ecdh_init(&bobcontext);

    //select curve

   mbedtls_ecdh_setup(&alicecontext, MBEDTLS_ECP_DP_SECP256R1);
   mbedtls_ecdh_setup(&bobcontext, MBEDTLS_ECP_DP_SECP256R1);

   //generate keypair
  int alicekeygen = mbedtls_ecdh_gen_public(&alicecontext.private_grp,&alicecontext.private_d,&alicecontext.private_Q,
		  mbedtls_ctr_drbg_random,&drbgcontext);

  if(alicekeygen!=0)
  {
	  printf("alice key geneeration failed");
	  return -1;
  }

  int bobkeygen = mbedtls_ecdh_gen_public(&bobcontext.private_grp,&bobcontext.private_d,&bobcontext.private_Q,
		  mbedtls_ctr_drbg_random,&drbgcontext);

    if(bobkeygen!=0)
    {
  	  printf("Bob key geneeration failed");
  	  return -1;
    }

    //alice generate shared keys

    int alicekeypair =  mbedtls_ecdh_compute_shared(&alicecontext.private_grp, &alicecontext.private_z,
    		&bobcontext.private_Q,
			&alicecontext.private_d,mbedtls_ctr_drbg_random,&drbgcontext);


    if(alicekeypair!=0)
       {
     	  printf("alice key pair geneeration failed");
     	  return -1;
       }

    //bob key pair

    int bobkeypair =  mbedtls_ecdh_compute_shared(&bobcontext.private_grp, &bobcontext.private_z,
        		&alicecontext.private_Q,
    			&bobcontext.private_d,mbedtls_ctr_drbg_random,&drbgcontext);


        if(bobkeypair!=0)
           {
         	  printf("alice key pair geneeration failed");
         	  return -1;
           }



        	print_mpi_data(&alicecontext.private_z);
        	print_mpi_data(&bobcontext.private_z);






    for (;;)
    {
    }
}

/* [] END OF FILE */
