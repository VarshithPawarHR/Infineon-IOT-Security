
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

//function write here

optiga_lib_status_t opstatus = OPTIGA_UTIL_BUSY;
void callbackfunc(void *callback_ctx, optiga_lib_status_t event)
{
	opstatus = event;
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

	//core functionalities


    //util creation
    optiga_util_t *optutil;
        optutil = optiga_util_create	(0,callbackfunc,NULL);

        if(optutil == NULL)
        {
        	printf("unsuccessful util creation \r\n");
        }

    //open application

    optiga_lib_status_t openstat = optiga_util_open_application	(optutil	,
    		0
    		);

    if(openstat !=0)
    {
    	printf("failure in opening application \r\n");
    	return -1;
    }

    while(opstatus == OPTIGA_UTIL_BUSY){}

    if(opstatus !=0)
    {
    	printf("unsuccessfull operation\r\n");
    	return -1;
    }

    opstatus = OPTIGA_UTIL_BUSY;

    //Crypt creation

    optiga_crypt_t* cryptcreate = optiga_crypt_create	(0,
    callbackfunc,
NULL
    );

    if(cryptcreate ==NULL)
    {
    	printf("failure in crypt creation \r\n");
    	return -1;
    }


    //Alice keypair gen

    optiga_key_id_t   aliceprivate = OPTIGA_KEY_ID_E0F2 ;
    uint8_t public_key[100] ={0};
    uint16_t publen = sizeof(public_key);

    optiga_lib_status_t alicekey = optiga_crypt_ecc_generate_keypair(cryptcreate,
    		OPTIGA_ECC_CURVE_NIST_P_256 ,
			OPTIGA_KEY_USAGE_KEY_AGREEMENT ,
   0,
    &aliceprivate,
    public_key,
    &publen
    );

    if(alicekey!=0)
    {
    	printf("failure alice key generation \r\n");
    	return -1;

    }

    while(opstatus == OPTIGA_UTIL_BUSY){}

       if(opstatus !=0)
       {
       	printf("unsuccessfull operation\r\n");
       	return -1;
       }

       opstatus = OPTIGA_UTIL_BUSY;

       //bob key generation

       optiga_key_id_t   bobprivate = OPTIGA_KEY_ID_E0F3 ;
          uint8_t publickey[100] ={0};
          uint16_t publiclen = sizeof(publickey);

          optiga_lib_status_t bobkey = optiga_crypt_ecc_generate_keypair(cryptcreate,
          		OPTIGA_ECC_CURVE_NIST_P_256 ,
      			OPTIGA_KEY_USAGE_KEY_AGREEMENT ,
         0,
          &bobprivate,
          publickey,
          &publiclen
          );

          if(bobkey!=0)
          {
          	printf("failure alice key generation \r\n");
          	return -1;

          }

          while(opstatus == OPTIGA_UTIL_BUSY){}

             if(opstatus !=0)
             {
             	printf("unsuccessfull operation\r\n");
             	return -1;
             }

             opstatus = OPTIGA_UTIL_BUSY;


             //alice keypair geenration

             public_key_from_host_t bobpub;
             bobpub.key_type =OPTIGA_ECC_CURVE_NIST_P_256 ;
             bobpub.length = publiclen;
             bobpub.public_key = publickey;

             uint8_t 	shared_secret[100]={0};



             optiga_lib_status_t aliceshared =  optiga_crypt_ecdh	(cryptcreate,
            		 OPTIGA_KEY_ID_E0F2 ,
             &bobpub,
             1,
            shared_secret
             );

             if(aliceshared !=0)
             {
            	 printf("failure in geenrating in alice shared \r\n");
            	 return -1;
             }

             while(opstatus == OPTIGA_UTIL_BUSY){}

                if(opstatus !=0)
                {
                	printf("unsuccessfull operation\r\n");
                	return -1;
                }

                opstatus = OPTIGA_UTIL_BUSY;



             //bob keypair generation

                public_key_from_host_t alicepub;
                            alicepub.key_type =OPTIGA_ECC_CURVE_NIST_P_256 ;
                            alicepub.length = publen;
                            alicepub.public_key = public_key;

                            uint8_t  	sharedsecret[100];



                            optiga_lib_status_t bobshared =  optiga_crypt_ecdh	(cryptcreate,
                           		 OPTIGA_KEY_ID_E0F3 ,
                            &alicepub,
                            1,
                           sharedsecret
                            );

                            if(bobshared !=0)
                            {
                           	 printf("failure in geenrating in bob shared \r\n");
                           	 return -1;
                            }

                            while(opstatus == OPTIGA_UTIL_BUSY){}

                               if(opstatus !=0)
                               {
                               	printf("unsuccessfull operation\r\n");
                               	return -1;
                               }

                               opstatus = OPTIGA_UTIL_BUSY;

                               print_uint8_data(sharedsecret,32);
                               printf("\r\n");
                               print_uint8_data(shared_secret,32);







}

/* [] END OF FILE */
