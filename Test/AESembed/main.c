
#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "ctr_drbg.h"
#include "entropy.h"
#include "aes.h"

//prototype of function
int randomnumbergenerator(uint8_t *key,size_t len);
void paddingfunc(uint8_t *data, uint16_t datalen, uint8_t* paddeddata ,uint16_t* totalpaddedlen);
int encryptfunc(mbedtls_aes_context* aescontext,uint8_t* paddeddata,uint8_t* iv,uint8_t* encrypt,uint16_t totalpaddedlen);
void decryptfunc(mbedtls_aes_context* aescontext,uint8_t* encrypt,uint8_t* ivcpy,uint8_t* decrypt,uint16_t totalpaddedlen);

//functions
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

int randomnumbergenerator(uint8_t *key,size_t len)
{

	//context creation
	mbedtls_ctr_drbg_context drbgcontext;
	mbedtls_entropy_context entropycontext;

	//initialization
	 mbedtls_ctr_drbg_init(&drbgcontext);
	 mbedtls_entropy_init(&entropycontext);

	 //seeding
	 mbedtls_ctr_drbg_seed(&drbgcontext,mbedtls_entropy_func,
			 &entropycontext, (const unsigned char*) "hello",5);

	 //random number

	int flag = mbedtls_ctr_drbg_random(&drbgcontext,key,sizeof(key));

	if(flag !=0)
	{
		printf("failure in generating random numbers \r\n");
		return -1;
	}
	return 0;



}

void  paddingfunc(uint8_t *data, uint16_t datalen, uint8_t* paddeddata ,uint16_t* totalpaddedlen)
{

	 memcpy(paddeddata,data,datalen);

	uint8_t paddedlen = 16- datalen%16;

	if(paddedlen==0)
	{
		paddedlen = 16;
	}

	for(int i = datalen;i<datalen+paddedlen;i++)
	{
		paddeddata[i] = paddedlen;
	}
	 *totalpaddedlen = datalen+paddedlen;


}

int encryptfunc(mbedtls_aes_context* aescontext,uint8_t* paddeddata,uint8_t* iv,uint8_t* encrypt,uint16_t totalpaddedlen)
{



	for(int i=0;i<totalpaddedlen;i+=16){
	  mbedtls_aes_crypt_cbc(aescontext,  MBEDTLS_AES_ENCRYPT,16,iv,
			 paddeddata+i, encrypt+i);
	}



	 return 0;


}

void decryptfunc(mbedtls_aes_context* aescontext,uint8_t* encrypt,uint8_t* ivcpy,uint8_t* decrypt,uint16_t totalpaddedlen)
{
	for(int i=0;i<totalpaddedlen;i+=16)
	{
	 mbedtls_aes_crypt_cbc(aescontext,MBEDTLS_AES_DECRYPT,16,ivcpy,
				 encrypt+i, decrypt+i);
	}



		uint8_t lastbyte = decrypt[totalpaddedlen-1];
		if(lastbyte<=16)
		{
			totalpaddedlen-=lastbyte;
			decrypt[totalpaddedlen] ='\0';
		}

		printf("original text is: %s", decrypt);



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

	//CORE FUNCTIONALITY STARTS


    //random number
    uint8_t key[16] ={0};
    randomnumbergenerator(key,sizeof(key));

   //AES implementation

   //context creation
   mbedtls_aes_context aescontext;

   //initialization
   mbedtls_aes_init(&aescontext);

   //key generation
   int checkkeygen = mbedtls_aes_setkey_enc(&aescontext,key,128);

   if(checkkeygen!=0)
   {
	   printf("encryption key not generated \r\n");
	   return -1;
   }

   const char* message = "hi kore wa nan desuka";
   uint8_t* data = (uint8_t*)message;
   uint16_t  datalen = strlen(message);

   uint8_t paddeddata[100] ={0};
  uint16_t totalpaddedlen = 0;


   //padding i have to do
  paddingfunc(data,datalen,paddeddata,&totalpaddedlen);

   //encryption timeeee

   uint8_t encrypt[100] ={0};
   uint8_t iv[16] = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6};

  uint8_t ivcpy[16] ={0};

  memcpy(ivcpy,iv,sizeof(iv));

  //encryption function


  encryptfunc(&aescontext,paddeddata,iv,encrypt,totalpaddedlen);

   printf("encrypted message is:\r\n");
  print_uint8_data(encrypt,totalpaddedlen);


  uint8_t decrypt[100] ={0};

  int keygenchecki = mbedtls_aes_setkey_dec(&aescontext, key, 128);
          if (keygenchecki != 0)
          {
              printf("Failure in setting AES encryption key:\r\n");
              return -1;
          }
 decryptfunc(&aescontext,encrypt,ivcpy,decrypt,totalpaddedlen);




    for (;;)
    {
    }
}

/* [] END OF FILE */
