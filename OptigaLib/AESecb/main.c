//ALL IMPORT FUNCTIONS HERE

#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "ecdh.h"
#include "optiga_util.h"
#include "optiga_crypt.h"

#define AES128_KEY_LENGTH 16

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

optiga_lib_status_t op_status = OPTIGA_UTIL_BUSY;
void handler_func(void *callback_ctx, optiga_lib_status_t event)
{
    op_status = event;
}

int main(void)
{
    cy_rslt_t result;

    // Init board
    result = cybsp_init();
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    __enable_irq();

    // Init UART
    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX, CY_RETARGET_IO_BAUDRATE);
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    printf("\x1b[2J\x1b[;H");
    printf("AES using ECB implementation\r\n\r\n");

    // Create util object
    optiga_util_t *optigautil = optiga_util_create(0, handler_func, NULL);
    if (optigautil == NULL)
    {
        printf("Unsuccessful util creation\r\n");
        return -1;
    }
    printf("Util creation successful\r\n");

    // Open application
    optiga_util_open_application(optigautil, 0);
    while (op_status == OPTIGA_UTIL_BUSY);
    if (op_status != OPTIGA_LIB_SUCCESS)
    {
        printf("Failed to open application\r\n");
        return -1;
    }
    printf("Application opened successfully\r\n");

    // Create crypt object
    optiga_crypt_t *op_crypt = optiga_crypt_create(0, handler_func, NULL);
    if (op_crypt == NULL)
    {
        printf("Unsuccessful crypt creation\r\n");
        return -1;
    }
    printf("Crypt object created successfully\r\n");

    // Generate AES key
    optiga_key_id_t key = OPTIGA_KEY_ID_SECRET_BASED;
    op_status = OPTIGA_UTIL_BUSY;

    optiga_lib_status_t keygen = optiga_crypt_symmetric_generate_key(
        op_crypt,
        OPTIGA_SYMMETRIC_AES_128,
        OPTIGA_KEY_USAGE_ENCRYPTION,
        0,
        &key
    );

    if (keygen != OPTIGA_LIB_SUCCESS)
    {
        printf("Key generation failed\r\n");
        return -1;
    }
    while (op_status == OPTIGA_UTIL_BUSY);
    if (op_status != OPTIGA_LIB_SUCCESS)
    {
        printf("Key generation operation failed\r\n");
        return -1;
    }
    printf("Key generated successfully\r\n");

    // Input
    const char* input_string = "12345CDEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint8_t* data = (uint8_t*)input_string;
    uint16_t data_len = strlen(input_string);

    // Padding calculation (PKCS#7 style)
    uint8_t padded_data[100] = {0};
    memcpy(padded_data, data, data_len);

    uint8_t padding_len = AES128_KEY_LENGTH - (data_len % AES128_KEY_LENGTH);
    if (padding_len == 0){
        padding_len = AES128_KEY_LENGTH;
    }

    for (int i = data_len; i < data_len + padding_len; i++)
    {
        padded_data[i] = padding_len;
    }

    uint32_t padded_total_len = data_len + padding_len;



    // Encrypt
    uint8_t encryptdata[100] = {0};
    uint32_t encrypt_len = sizeof(encryptdata);

    op_status = OPTIGA_UTIL_BUSY;
    optiga_lib_status_t encrypt_state = optiga_crypt_symmetric_encrypt(
        op_crypt,
        OPTIGA_SYMMETRIC_ECB,
        OPTIGA_KEY_ID_SECRET_BASED,
        padded_data,
        padded_total_len,
        NULL,
        0,
        NULL,
        0,
        encryptdata,
        &encrypt_len
    );

    if (encrypt_state != OPTIGA_LIB_SUCCESS)
    {
        printf("Encryption failed\r\n");
        return -1;
    }
    while (op_status == OPTIGA_UTIL_BUSY);
    if (op_status != OPTIGA_LIB_SUCCESS)
    {
        printf("Encryption operation failed\r\n");
        return -1;
    }

    printf("Encryption successful\r\nEncrypted data:");
    print_uint8_data(encryptdata, encrypt_len);

    // Decrypt
    uint8_t plain_data[100] = {0};
    uint32_t plain_len = sizeof(plain_data);

    op_status = OPTIGA_UTIL_BUSY;
    optiga_lib_status_t decrypt_state = optiga_crypt_symmetric_decrypt(
        op_crypt,
        OPTIGA_SYMMETRIC_ECB,
        OPTIGA_KEY_ID_SECRET_BASED,
        encryptdata,
        encrypt_len,
        NULL,
        0,
        NULL,
        0,
        plain_data,
        &plain_len
    );

    if (decrypt_state != OPTIGA_LIB_SUCCESS)
    {
        printf("Decryption failed\r\n");
        return -1;
    }
    while (op_status == OPTIGA_UTIL_BUSY);
    if (op_status != OPTIGA_LIB_SUCCESS)
    {
        printf("Decryption operation failed\r\n");
        return -1;
    }

    // Remove PKCS#7 padding
    uint8_t last_byte = plain_data[plain_len - 1];
    if (last_byte <= AES128_KEY_LENGTH)
    {
        plain_len -= last_byte;
        plain_data[plain_len] = '\0'; // Null-terminate
    }

    printf("Decryption successful\r\nDecrypted string: %s\r\n", plain_data);

    for (;;)
    {
        // Stay in infinite loop
    }
}


//you have to first add then also remove the padding also
