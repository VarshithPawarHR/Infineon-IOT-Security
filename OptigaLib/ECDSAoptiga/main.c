
#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "optiga_util.h"
#include "optiga_crypt.h"

/******************************************************************************
* Macros
*******************************************************************************/


/*******************************************************************************
* Global Variables
*******************************************************************************/


/*******************************************************************************
* Function Prototypes
*******************************************************************************/

void print_uint8_data(uint8_t* data, size_t len){
	for(uint8_t i=0;i < len;i++){
		if((i%16 == 0)){
			printf("\r\n");
		}
		printf("%d ",*(data+i));
	}
	printf("\r\n");

}
/*******************************************************************************
* Function Definitions
*******************************************************************************/
optiga_lib_status_t op_status = OPTIGA_UTIL_BUSY;
optiga_lib_status_t api_status;


void func(void* callback_ctx, optiga_lib_status_t event){
         	   op_status = event;

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

#if defined (CY_DEVICE_SECURE) && defined (CY_USING_HAL)
    cyhal_wdt_t wdt_obj;

    /* Clear watchdog timer so that it doesn't trigger a reset */
    result = cyhal_wdt_init(&wdt_obj, cyhal_wdt_get_max_timeout_ms());
    CY_ASSERT(CY_RSLT_SUCCESS == result);
    cyhal_wdt_free(&wdt_obj);
#endif

    /* Initialize the device and board peripherals */
    result = cybsp_init();

    /* Board init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Enable global interrupts */
    __enable_irq();

    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX,
          		CY_RETARGET_IO_BAUDRATE);


       if (result != CY_RSLT_SUCCESS)
       	{
       	   CY_ASSERT(0);
       	}

       printf("\x1b[2J\x1b[;H");

       printf("Hello World\r\n");


       optiga_util_t* opt_util = optiga_util_create(0, func, NULL);
       if(opt_util==NULL){
               	   printf("OPTIGA UTIL COULDNT BE CREATED\r\n");
               	   CY_ASSERT(0);
       }

       api_status = optiga_util_open_application(opt_util, 0);

       if(api_status!=OPTIGA_UTIL_SUCCESS){
               	   printf("API STATUS NOT SUCESSFULL\r\n");
               	      	   CY_ASSERT(0);
       }

       while(op_status==OPTIGA_UTIL_BUSY);

       if(op_status == OPTIGA_UTIL_SUCCESS){
    	   op_status = OPTIGA_CRYPT_BUSY;
           printf("API OPERATION SUCESSFULL\r\n");
          }else{
               	   printf("API OPERATION FAILURE\r\n");
               	  CY_ASSERT(0);
       }

       optiga_crypt_t* opt_crypt = optiga_crypt_create(0,func,NULL);

                  if(opt_crypt==NULL){
                          	   printf("OPTIGA UTIL COULDNT BE CREATED\r\n");
                          	   CY_ASSERT(0);
           }



                  //Code here
                  uint8_t data[] = "hi there hello woerld";
                  uint8_t hashedData[32]={0};
                  uint8_t hashedDataLength =sizeof(hashedData)/sizeof(hashedData[0]);
                  optiga_hash_type_t hash_algo = OPTIGA_HASH_TYPE_SHA_256 ;
                  hash_data_from_host_t host_data;
                  host_data.buffer = data;
                  host_data.length = sizeof(data);
                  optiga_key_id_t alice_private_key = OPTIGA_KEY_ID_E0F2;
                  uint8_t alice_public_key[100]={0};
                  uint16_t alice_public_key_length = sizeof(alice_public_key)/sizeof(alice_public_key[0]);
                  uint8_t signature[256]={0};

                  uint16_t signature_length = sizeof(signature);
                  optiga_ecc_curve_t curve_id = OPTIGA_ECC_CURVE_NIST_P_256 ;







                  api_status = optiga_crypt_hash(opt_crypt, hash_algo,OPTIGA_CRYPT_HOST_DATA ,&host_data,  hashedData);

                  if(api_status!=OPTIGA_UTIL_SUCCESS){
                                	   printf("API STATUS NOT SUCESSFULL\r\n");
                                	      	   CY_ASSERT(0);
                        }

                        while(op_status==OPTIGA_UTIL_BUSY);

                        if(op_status == OPTIGA_UTIL_SUCCESS){
                     	   op_status = OPTIGA_CRYPT_BUSY;
                            printf("API OPERATION SUCESSFULL\r\n");
                           }else{
                                	   printf("API OPERATION FAILURE\r\n");
                                	  CY_ASSERT(0);
                        }
                        printf("HASHED DATA\r\n");
                       print_uint8_data(hashedData, 40);






//
                       api_status = optiga_crypt_ecc_generate_keypair(opt_crypt, curve_id, OPTIGA_KEY_USAGE_SIGN, 0, (void *)&alice_private_key , alice_public_key, &alice_public_key_length);

                       if(api_status!=OPTIGA_UTIL_SUCCESS){
                                                      	   printf("API STATUS NOT SUCESSFULL\r\n");
                                                      	      	   CY_ASSERT(0);
                                              }

                                              while(op_status==OPTIGA_UTIL_BUSY);

                                              if(op_status == OPTIGA_UTIL_SUCCESS){
                                           	   op_status = OPTIGA_CRYPT_BUSY;
                                                  printf("API OPERATION SUCESSFULL\r\n");
                                                 }else{
                                                      	   printf("API OPERATION FAILURE\r\n");
                                                      	  CY_ASSERT(0);
                                              }
                                              printf("ALICE PUBLIC KEY\r\n");
                                              print_uint8_data(alice_public_key, alice_public_key_length);

//
//
                       api_status = optiga_crypt_ecdsa_sign(opt_crypt, hashedData, hashedDataLength , alice_private_key, signature, &signature_length);
//
                       if(api_status!=OPTIGA_UTIL_SUCCESS){
                                            printf("API STATUS NOT SUCESSFULL\r\n");
                                            CY_ASSERT(0);
                          }

                      while(op_status==OPTIGA_UTIL_BUSY){}

                       if(op_status == OPTIGA_UTIL_SUCCESS){
                        op_status = OPTIGA_CRYPT_BUSY;
                         printf("API OPERATION SUCESSFULL\r\n");
                               }else{
                              printf("API OPERATION FAILURE\r\n");
                           CY_ASSERT(0);
                     }


                       printf("Signature: \r\n");
                       print_uint8_data(signature, signature_length);


                       public_key_from_host_t pbAlice;

                       pbAlice.public_key = alice_public_key;
                       pbAlice.length = alice_public_key_length;
                       pbAlice.key_type=curve_id;

                       api_status = optiga_crypt_ecdsa_verify(opt_crypt, hashedData, hashedDataLength, signature, signature_length, OPTIGA_CRYPT_HOST_DATA,(const void *)&pbAlice);

                       if(api_status!=OPTIGA_UTIL_SUCCESS){
                                                                printf("API STATUS NOT SUCESSFULL\r\n");
                                                                CY_ASSERT(0);
                                              }

                                          while(op_status==OPTIGA_UTIL_BUSY){}

                                           if(op_status == OPTIGA_UTIL_SUCCESS){
                                            op_status = OPTIGA_CRYPT_BUSY;
                                             printf("API OPERATION OF VERIFY SUCESSFULL\r\n");
                                                   }else{
                                                  printf("API OPERATION VERIFY FAILURE\r\n");
                                               CY_ASSERT(0);
                                         }


                  api_status = optiga_util_close_application(opt_util, 0);
                            if(api_status!=OPTIGA_UTIL_SUCCESS){
                                    	   printf("API STATUS NOT SUCESSFULL AT CLOSING\r\n");
                                    	      	   CY_ASSERT(0);
                                       }
                                       while(op_status==OPTIGA_UTIL_BUSY);

                                       if(op_status == OPTIGA_UTIL_SUCCESS){
                                    	   printf("API OPERATION FOR CLOSING SUCESSFULL\r\n");
                                       }else{
                                    	   printf("API OPERATION FAILURE FOR CLOSING\r\n");
                                    	  CY_ASSERT(0);
                                       }

                                       api_status = optiga_crypt_destroy(opt_crypt);

                                                  if(api_status != OPTIGA_LIB_SUCCESS){
                                                  	printf("CRYPT DESTROY FAILURE\r\n");
                                                  	CY_ASSERT(0);
                                                  }


                                       optiga_util_destroy(opt_util);

    for (;;)
    {
    }
}

/* [] END OF FILE */
