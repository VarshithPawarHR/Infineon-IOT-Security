#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "optiga_util.h"
#include "optiga_crypt.h"

optiga_lib_status_t op_status = OPTIGA_UTIL_BUSY;
optiga_lib_status_t api_status;

void optiga_callback(void* callback_ctx, optiga_lib_status_t event)
{
    op_status = event;
}

void print_uint8_data(uint8_t* data, size_t len)
{
    for(uint8_t i = 0; i < len; i++)
    {
        if (i % 16 == 0) printf("\r\n");
        printf("%d ", data[i]);
    }
    printf("\r\n");
}

void hash_data(optiga_crypt_t* opt_crypt, uint8_t* input, uint8_t* output, size_t input_len)
{
    optiga_hash_type_t hash_algo = OPTIGA_HASH_TYPE_SHA_256;
    hash_data_from_host_t host_data = { input, input_len };

    api_status = optiga_crypt_hash(opt_crypt, hash_algo, OPTIGA_CRYPT_HOST_DATA, &host_data, output);
    if (api_status != OPTIGA_UTIL_SUCCESS) {
        printf("HASH API FAILED\r\n"); CY_ASSERT(0);
    }

    while (op_status == OPTIGA_UTIL_BUSY);
    if (op_status != OPTIGA_UTIL_SUCCESS) {
        printf("HASH OPERATION FAILED\r\n"); CY_ASSERT(0);
    }

    op_status = OPTIGA_CRYPT_BUSY;
    printf("HASHED DATA:\r\n");
    print_uint8_data(output, 32);
}

void generate_key_pair(optiga_crypt_t* opt_crypt, optiga_key_id_t key_id, uint8_t* public_key, uint16_t* public_key_len)
{
    api_status = optiga_crypt_ecc_generate_keypair(opt_crypt, OPTIGA_ECC_CURVE_NIST_P_256,
                                                    OPTIGA_KEY_USAGE_SIGN, 0,
                                                    (void*)&key_id, public_key, public_key_len);
    if (api_status != OPTIGA_UTIL_SUCCESS) {
        printf("KEYGEN API FAILED\r\n"); CY_ASSERT(0);
    }

    while (op_status == OPTIGA_UTIL_BUSY);
    if (op_status != OPTIGA_UTIL_SUCCESS) {
        printf("KEYGEN OPERATION FAILED\r\n"); CY_ASSERT(0);
    }

    op_status = OPTIGA_CRYPT_BUSY;
    printf("ALICE PUBLIC KEY:\r\n");
    print_uint8_data(public_key, *public_key_len);
}

void sign_data(optiga_crypt_t* opt_crypt, uint8_t* hashed_data, uint8_t hashed_len, optiga_key_id_t key_id, uint8_t* signature, uint16_t* sig_len)
{
    api_status = optiga_crypt_ecdsa_sign(opt_crypt, hashed_data, hashed_len, key_id, signature, sig_len);
    if (api_status != OPTIGA_UTIL_SUCCESS) {
        printf("SIGN API FAILED\r\n"); CY_ASSERT(0);
    }

    while (op_status == OPTIGA_UTIL_BUSY);
    if (op_status != OPTIGA_UTIL_SUCCESS) {
        printf("SIGN OPERATION FAILED\r\n"); CY_ASSERT(0);
    }

    op_status = OPTIGA_CRYPT_BUSY;
    printf("SIGNATURE:\r\n");
    print_uint8_data(signature, 32);
}

void verify_signature(optiga_crypt_t* opt_crypt, uint8_t* hashed_data, uint8_t hashed_len, uint8_t* signature, uint16_t sig_len, uint8_t* public_key, uint16_t public_key_len)
{
    public_key_from_host_t pb = {
        .public_key = public_key,
        .length = public_key_len,
        .key_type = OPTIGA_ECC_CURVE_NIST_P_256
    };

    api_status = optiga_crypt_ecdsa_verify(opt_crypt, hashed_data, hashed_len, signature, sig_len, OPTIGA_CRYPT_HOST_DATA, (const void*)&pb);
    if (api_status != OPTIGA_UTIL_SUCCESS) {
        printf("VERIFY API FAILED\r\n"); CY_ASSERT(0);
    }

    while (op_status == OPTIGA_UTIL_BUSY);
    if (op_status != OPTIGA_UTIL_SUCCESS) {
        printf("VERIFY OPERATION FAILED\r\n"); CY_ASSERT(0);
    }

    op_status = OPTIGA_CRYPT_BUSY;
    printf("VERIFY SUCCESSFUL\r\n");
}

int main(void)
{
    cy_rslt_t result;

#if defined (CY_DEVICE_SECURE) && defined (CY_USING_HAL)
    cyhal_wdt_t wdt_obj;
    result = cyhal_wdt_init(&wdt_obj, cyhal_wdt_get_max_timeout_ms());
    CY_ASSERT(result == CY_RSLT_SUCCESS);
    cyhal_wdt_free(&wdt_obj);
#endif

    result = cybsp_init();
    if (result != CY_RSLT_SUCCESS) CY_ASSERT(0);
    __enable_irq();

    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX, CY_RETARGET_IO_BAUDRATE);
    if (result != CY_RSLT_SUCCESS) CY_ASSERT(0);

    printf("\x1b[2J\x1b[;H");


    optiga_util_t* opt_util = optiga_util_create(0, optiga_callback, NULL);
    CY_ASSERT(opt_util != NULL);

    api_status = optiga_util_open_application(opt_util, 0);
    if (api_status != OPTIGA_UTIL_SUCCESS) CY_ASSERT(0);
    while (op_status == OPTIGA_UTIL_BUSY);
    if (op_status != OPTIGA_UTIL_SUCCESS) CY_ASSERT(0);
    op_status = OPTIGA_CRYPT_BUSY;

    optiga_crypt_t* opt_crypt = optiga_crypt_create(0, optiga_callback, NULL);
    CY_ASSERT(opt_crypt != NULL);

    uint8_t data[] = "hi there hello woerld";
    uint8_t hashedData[32] = {0};
    uint8_t signature[256] = {0};
    uint8_t hashed_len = sizeof(hashedData);
    uint16_t sig_len = sizeof(signature);
    uint8_t public_key[100] = {0};
    uint16_t public_key_len = sizeof(public_key);
    optiga_key_id_t key_id = OPTIGA_KEY_ID_E0F2;

    hash_data(opt_crypt, data, hashedData, sizeof(data));
    generate_key_pair(opt_crypt, key_id, public_key, &public_key_len);
    sign_data(opt_crypt, hashedData, hashed_len, key_id, signature, &sig_len);
    verify_signature(opt_crypt, hashedData, hashed_len, signature, sig_len, public_key, public_key_len);

    api_status = optiga_util_close_application(opt_util, 0);
    CY_ASSERT(api_status == OPTIGA_UTIL_SUCCESS);
    while (op_status == OPTIGA_UTIL_BUSY);


    optiga_crypt_destroy(opt_crypt);
    optiga_util_destroy(opt_util);

    for (;;) {}
}
