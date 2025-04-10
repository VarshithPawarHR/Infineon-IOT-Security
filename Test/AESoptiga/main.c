#if defined(CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "ecdh.h"
#include "optiga_util.h"
#include "optiga_crypt.h"
#include <string.h>
#include <stdio.h>

#define AES128_KEY_LENGTH 16
#define MAX_DATA_LEN 100

optiga_lib_status_t op_status = OPTIGA_UTIL_BUSY;

void handler_func(void *callback_ctx, optiga_lib_status_t event)
{
    op_status = event;
}

void print_uint8_data(uint8_t *data, size_t len)
{
    for (uint8_t i = 0; i < len; i++)
    {
        if ((i % 16) == 0)
            printf("\r\n");
        printf("0x%02X ", data[i]);
    }
    printf("\r\n");
}

// === Modular Functions ===

optiga_lib_status_t generate_aes_key(optiga_crypt_t *op_crypt, optiga_key_id_t *key_out)
{
    *key_out = OPTIGA_KEY_ID_SECRET_BASED;
    op_status = OPTIGA_UTIL_BUSY;

    optiga_lib_status_t status = optiga_crypt_symmetric_generate_key(
        op_crypt,
        OPTIGA_SYMMETRIC_AES_128,
        OPTIGA_KEY_USAGE_ENCRYPTION,
        0,
        key_out
    );

    if (status != OPTIGA_LIB_SUCCESS) return status;
    while (op_status == OPTIGA_UTIL_BUSY);
    return op_status;
}

uint32_t apply_pkcs7_padding(uint8_t *output, const uint8_t *input, uint32_t input_len)
{
    memcpy(output, input, input_len);
    uint8_t padding_len = AES128_KEY_LENGTH - (input_len % AES128_KEY_LENGTH);
    if (padding_len == 0)
        padding_len = AES128_KEY_LENGTH;

    for (uint32_t i = input_len; i < input_len + padding_len; i++)
        output[i] = padding_len;

    return input_len + padding_len;
}

optiga_lib_status_t aes_encrypt_ecb(optiga_crypt_t *op_crypt, optiga_key_id_t key_id,
                                    uint8_t *input, uint32_t input_len,
                                    uint8_t *output, uint32_t *output_len)
{
    op_status = OPTIGA_UTIL_BUSY;
    optiga_lib_status_t status = optiga_crypt_symmetric_encrypt(
        op_crypt,
        OPTIGA_SYMMETRIC_ECB,
        key_id,
        input,
        input_len,
        NULL,
        0,
        NULL,
        0,
        output,
        output_len
    );

    if (status != OPTIGA_LIB_SUCCESS) return status;
    while (op_status == OPTIGA_UTIL_BUSY);
    return op_status;
}

optiga_lib_status_t aes_decrypt_ecb(optiga_crypt_t *op_crypt, optiga_key_id_t key_id,
                                    uint8_t *input, uint32_t input_len,
                                    uint8_t *output, uint32_t *output_len)
{
    op_status = OPTIGA_UTIL_BUSY;
    optiga_lib_status_t status = optiga_crypt_symmetric_decrypt(
        op_crypt,
        OPTIGA_SYMMETRIC_ECB,
        key_id,
        input,
        input_len,
        NULL,
        0,
        NULL,
        0,
        output,
        output_len
    );

    if (status != OPTIGA_LIB_SUCCESS) return status;
    while (op_status == OPTIGA_UTIL_BUSY);
    return op_status;
}

void remove_pkcs7_padding(uint8_t *data, uint32_t *len)
{
    uint8_t padding = data[*len - 1];
    if (padding <= AES128_KEY_LENGTH)
    {
        *len -= padding;
        data[*len] = '\0'; // null-terminate for string printing
    }
}

// === Main ===

int main(void)
{
    cy_rslt_t result = cybsp_init();
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    __enable_irq();

    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX, CY_RETARGET_IO_BAUDRATE);
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    printf("\x1b[2J\x1b[;H");
    printf("AES using ECB implementation\r\n\r\n");

    // Create util object
    optiga_util_t *optigautil = optiga_util_create(0, handler_func, NULL);
    if (!optigautil)
    {
        printf("Util creation failed\r\n");
        return -1;
    }

    optiga_util_open_application(optigautil, 0);
    while (op_status == OPTIGA_UTIL_BUSY);
    if (op_status != OPTIGA_LIB_SUCCESS)
    {
        printf("Application open failed\r\n");
        return -1;
    }

    // Create crypt object
    optiga_crypt_t *op_crypt = optiga_crypt_create(0, handler_func, NULL);
    if (!op_crypt)
    {
        printf("Crypt object creation failed\r\n");
        return -1;
    }

    // Generate key
    optiga_key_id_t key_id;
    if (generate_aes_key(op_crypt, &key_id) != OPTIGA_LIB_SUCCESS)
    {
        printf("AES key generation failed\r\n");
        return -1;
    }
    printf("AES key generated successfully\r\n");

    // Input + Padding
    const char *input = "12345CDEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint8_t padded_input[MAX_DATA_LEN] = {0};
    uint32_t padded_len = apply_pkcs7_padding(padded_input, (uint8_t *)input, strlen(input));

    // Encrypt
    uint8_t encrypted[MAX_DATA_LEN] = {0};
    uint32_t encrypted_len = sizeof(encrypted);

    if (aes_encrypt_ecb(op_crypt, key_id, padded_input, padded_len, encrypted, &encrypted_len) != OPTIGA_LIB_SUCCESS)
    {
        printf("Encryption failed\r\n");
        return -1;
    }
    printf("Encryption successful\r\nEncrypted data:");
    print_uint8_data(encrypted, encrypted_len);

    // Decrypt
    uint8_t decrypted[MAX_DATA_LEN] = {0};
    uint32_t decrypted_len = sizeof(decrypted);

    if (aes_decrypt_ecb(op_crypt, key_id, encrypted, encrypted_len, decrypted, &decrypted_len) != OPTIGA_LIB_SUCCESS)
    {
        printf("Decryption failed\r\n");
        return -1;
    }

    remove_pkcs7_padding(decrypted, &decrypted_len);
    printf("Decryption successful\r\nDecrypted string: %s\r\n", decrypted);

    while (1); // Infinite loop
}
