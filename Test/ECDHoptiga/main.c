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
    size_t buflen = 0;
    mbedtls_ecp_point_write_binary(grp, data, MBEDTLS_ECP_PF_UNCOMPRESSED, &buflen, buffer, sizeof(buffer));
    print_uint8_data(buffer, buflen);
}

optiga_lib_status_t opstatus = OPTIGA_UTIL_BUSY;

void callbackfunc(void *callback_ctx, optiga_lib_status_t event)
{
    opstatus = event;
}

void wait_for_completion()
{
    while (opstatus == OPTIGA_UTIL_BUSY);
    if (opstatus != OPTIGA_LIB_SUCCESS)
    {
        printf("Unsuccessful operation\r\n");
        CY_ASSERT(0);
    }
    opstatus = OPTIGA_UTIL_BUSY;
}

optiga_util_t* initialize_util()
{
    optiga_util_t *util = optiga_util_create(0, callbackfunc, NULL);
    if (util == NULL)
    {
        printf("Util creation failed\r\n");
        CY_ASSERT(0);
    }

    if (optiga_util_open_application(util, 0) != 0)
    {
        printf("Failed to open application\r\n");
        CY_ASSERT(0);
    }

    wait_for_completion();
    return util;
}

optiga_crypt_t* initialize_crypto()
{
    optiga_crypt_t *crypt = optiga_crypt_create(0, callbackfunc, NULL);
    if (crypt == NULL)
    {
        printf("Crypto context creation failed\r\n");
        CY_ASSERT(0);
    }
    return crypt;
}

void generate_keypair(optiga_crypt_t* crypt, optiga_key_id_t key_id, uint8_t* public_key, uint16_t* publen)
{
    if (optiga_crypt_ecc_generate_keypair(crypt,
                                          OPTIGA_ECC_CURVE_NIST_P_256,
                                          OPTIGA_KEY_USAGE_KEY_AGREEMENT,
                                          0,
                                          &key_id,
                                          public_key,
                                          publen) != 0)
    {
        printf("Keypair generation failed\r\n");
        CY_ASSERT(0);
    }

    wait_for_completion();
}

void generate_shared_secret(optiga_crypt_t* crypt, optiga_key_id_t private_key_id, uint8_t* peer_pubkey, uint16_t peer_len, uint8_t* shared_secret)
{
    public_key_from_host_t pubkey_info = {
        .key_type = OPTIGA_ECC_CURVE_NIST_P_256,
        .length = peer_len,
        .public_key = peer_pubkey
    };

    if (optiga_crypt_ecdh(crypt, private_key_id, &pubkey_info, 1, shared_secret) != 0)
    {
        printf("Shared secret generation failed\r\n");
        CY_ASSERT(0);
    }

    wait_for_completion();
}

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

    optiga_util_t* util = initialize_util();
    optiga_crypt_t* crypt = initialize_crypto();

    optiga_key_id_t alice_private = OPTIGA_KEY_ID_E0F2;
    uint8_t alice_public[100] = {0};
    uint16_t alice_pub_len = sizeof(alice_public);
    generate_keypair(crypt, alice_private, alice_public, &alice_pub_len);

    optiga_key_id_t bob_private = OPTIGA_KEY_ID_E0F3;
    uint8_t bob_public[100] = {0};
    uint16_t bob_pub_len = sizeof(bob_public);
    generate_keypair(crypt, bob_private, bob_public, &bob_pub_len);

    uint8_t alice_shared[100] = {0};
    generate_shared_secret(crypt, alice_private, bob_public, bob_pub_len, alice_shared);

    uint8_t bob_shared[100] = {0};
    generate_shared_secret(crypt, bob_private, alice_public, alice_pub_len, bob_shared);

    printf("Alice Shared Secret:");
    print_uint8_data(alice_shared, 32);

    printf("Bob Shared Secret:");
    print_uint8_data(bob_shared, 32);

    return 0;
}
