
#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "ecdh.h"
#include "optiga_util.h"
#include "optiga_crypt.h"


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
optiga_lib_status_t op_status = OPTIGA_UTIL_BUSY;

void caller_func(void *callback_ctx, optiga_lib_status_t event)
{
	op_status = event;
}


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

    //UTIL CREATION

    optiga_util_t *optutil;
    optutil = optiga_util_create	(0,caller_func,NULL);

    if(optutil == NULL)
    {
    	printf("unsuccessful util creation \r\n");
    }

    //OPEN APPLICATION

    optiga_lib_status_t optigaopen = optiga_util_open_application	(optutil,
    0
    );

    if(optigaopen != OPTIGA_UTIL_SUCCESS)
    {
    	printf("failure in opening \r\n");
    	return -1;
    }

    while(op_status == OPTIGA_UTIL_BUSY){}

    if(op_status != 0)
    {
    	printf("unsuccessful operation \r\n");
    }

    op_status = OPTIGA_UTIL_BUSY;

    //CRYPT CREATION

    optiga_crypt_t* cryptcreate =  optiga_crypt_create	(0,
    caller_func,
    NULL
    );

    if(cryptcreate ==NULL)
    {
    	printf("failed creating crypt \r\n");
    	return -1;
    }

    //ALICE KEYPAIR GEENRATION
    optiga_key_id_t aliceprivkey = OPTIGA_KEY_ID_E0F2 ;
    uint8_t alicepublic_key[100] ={0};
    uint16_t 	alicepublic_key_length = sizeof(alicepublic_key);


    optiga_lib_status_t alicekeygen = optiga_crypt_ecc_generate_keypair	(cryptcreate,
    		OPTIGA_ECC_CURVE_NIST_P_256 ,
			OPTIGA_KEY_USAGE_KEY_AGREEMENT ,
    0,
    &aliceprivkey,
    alicepublic_key,
    &alicepublic_key_length
    );

    if(alicekeygen!=0)
    {
    	printf("failure in generating key of alice \r\n");
    	return -1;
    }

    while(op_status == OPTIGA_UTIL_BUSY){}

       if(op_status != 0)
       {
       	printf("unsuccessful operation \r\n");
       	return -1;
       }

       op_status = OPTIGA_UTIL_BUSY;

    //BOB KEYPAIR GENERATION


        optiga_key_id_t bobprivkey = OPTIGA_KEY_ID_E0F3 ;
        uint8_t bobpublic_key[100] ={0};
        uint16_t 	bobpublic_key_length = sizeof(bobpublic_key);


        optiga_lib_status_t bobkeygen = optiga_crypt_ecc_generate_keypair	(cryptcreate,
        		OPTIGA_ECC_CURVE_NIST_P_256 ,
    			OPTIGA_KEY_USAGE_KEY_AGREEMENT ,
        0,
        &bobprivkey,
        bobpublic_key,
        &bobpublic_key_length
        );

        if(bobkeygen!=0)
            {
            	printf("failure in generating key of alice \r\n");
            	return -1;
            }

            while(op_status == OPTIGA_UTIL_BUSY){}

               if(op_status != 0)
               {
               	printf("unsuccessful operation \r\n");
               	return -1;
               }

               op_status = OPTIGA_UTIL_BUSY;


        //ALICE SHARED
               public_key_from_host_t bobpub;
               bobpub.public_key = bobpublic_key;
               	bobpub.length = bobpublic_key_length;
               	bobpub.key_type = OPTIGA_ECC_CURVE_NIST_P_256;
               uint8_t aliceshared_secret[100]={0};


               optiga_lib_status_t aliceshared = optiga_crypt_ecdh	(cryptcreate,
            		   aliceprivkey,
					   &bobpub,
               1,
               aliceshared_secret
               );
               if(aliceshared !=0)
                           {
                           	printf("failure in generating shared key of alice \r\n");
                           	return -1;
                           }

                           while(op_status == OPTIGA_UTIL_BUSY){}

                              if(op_status != 0)
                              {
                              	printf("unsuccessful operation \r\n");
                              	return -1;
                              }

                              print_uint8_data(aliceshared_secret, 32);

                              op_status = OPTIGA_UTIL_BUSY;

                              //BOB SHARED KEY

                              public_key_from_host_t alicepub;
                              alicepub.public_key = alicepublic_key;
                                             	alicepub.length = alicepublic_key_length;
                                             	alicepub.key_type = OPTIGA_ECC_CURVE_NIST_P_256;
                                             uint8_t bobshared_secret[100]={0};


                                             optiga_lib_status_t bobshared = optiga_crypt_ecdh	(cryptcreate,
                                          		   bobprivkey,
                              					   &alicepub,
                                             1,
                                             bobshared_secret
                                             );
                                             if(bobshared !=0)
                                                         {
                                                         	printf("failure in generating shared key of alice \r\n");
                                                         	return -1;
                                                         }

                                                         while(op_status == OPTIGA_UTIL_BUSY){}

                                                            if(op_status != 0)
                                                            {
                                                            	printf("unsuccessful operation \r\n");
                                                            	return -1;
                                                            }

                                                            op_status = OPTIGA_UTIL_BUSY;

                                                            print_uint8_data(bobshared_secret, 32);













}

/* [] END OF FILE */
