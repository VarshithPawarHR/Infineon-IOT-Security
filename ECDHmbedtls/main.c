#if defined (CY_USING_HAL)
#include "cyhal.h"
#endif
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "ecp.h"
#include "ecdh.h"
#include "ctr_drbg.h"
#include "entropy.h"

/**************************
* Function Prototypes
***************************/
void print_uint8_data(uint8_t* data, size_t len);
void print_mpi_data(mbedtls_mpi* data);
void print_ecp_point_data(mbedtls_ecp_point* data, mbedtls_ecp_group *grp);
void initialize_uart(void);
void initialize_rng(mbedtls_ctr_drbg_context *random_context, mbedtls_entropy_context *entropy_context);
void initialize_ecdh_context(mbedtls_ecdh_context *ctx);
void generate_keypair(mbedtls_ecdh_context *ctx, mbedtls_ctr_drbg_context *drbg_ctx);
void compute_shared_secret(mbedtls_ecdh_context *ctx, const mbedtls_ecp_point *peer_public, const mbedtls_mpi *private_d, mbedtls_ctr_drbg_context *drbg_ctx);
void compare_shared_secrets(mbedtls_mpi *z1, mbedtls_mpi *z2);

/***************************
* Function Definitions
***************************/
void print_uint8_data(uint8_t* data, size_t len)
{
    for (uint8_t i = 0; i < len; i++)
    {
        if ((i % 16) == 0) printf("\r\n");
        printf("0x%02X ", *(data + i));
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

void initialize_uart(void)
{
    cy_rslt_t result;
    result = cybsp_init();
    if (result != CY_RSLT_SUCCESS) CY_ASSERT(0);

    __enable_irq();

    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX, CY_RETARGET_IO_BAUDRATE);
    if (result != CY_RSLT_SUCCESS) CY_ASSERT(0);

    printf("\x1b[2J\x1b[;H");
    printf("PSOC_PROTOTYPING_KIT template is ready to start.\r\n");
}

void initialize_rng(mbedtls_ctr_drbg_context *random_context, mbedtls_entropy_context *entropy_context)
{
    mbedtls_ctr_drbg_init(random_context);
    mbedtls_entropy_init(entropy_context);
    mbedtls_ctr_drbg_seed(random_context, mbedtls_entropy_func, entropy_context, "hibee", 5);
}

void initialize_ecdh_context(mbedtls_ecdh_context *ctx)
{
    mbedtls_ecdh_init(ctx);
    mbedtls_ecdh_setup(ctx, MBEDTLS_ECP_DP_SECP256R1);
}

void generate_keypair(mbedtls_ecdh_context *ctx, mbedtls_ctr_drbg_context *drbg_ctx)
{
    mbedtls_ecdh_gen_public(&ctx->private_grp, &ctx->private_d, &ctx->private_Q, mbedtls_ctr_drbg_random, drbg_ctx);
}

void compute_shared_secret(mbedtls_ecdh_context *ctx, const mbedtls_ecp_point *peer_public, const mbedtls_mpi *private_d, mbedtls_ctr_drbg_context *drbg_ctx)
{
    mbedtls_ecdh_compute_shared(&ctx->private_grp, &ctx->private_z, peer_public, private_d, mbedtls_ctr_drbg_random, drbg_ctx);
}

void compare_shared_secrets(mbedtls_mpi *z1, mbedtls_mpi *z2)
{
    int flag = mbedtls_mpi_cmp_mpi(z1, z2);
    if (flag == 0)
    {
        printf("\r\nBoth secret keys are equal.\r\n");
    }
    else
    {
        printf("\r\nSecret keys are NOT equal.\r\n");
    }
    print_mpi_data(z1);
    print_mpi_data(z2);
}

/***************************
* Main Function
***************************/
int main(void)
{
    mbedtls_ctr_drbg_context random_context;
    mbedtls_entropy_context entropy_context;
    mbedtls_ecdh_context Alice_context, Bob_context;

    initialize_uart();
    initialize_rng(&random_context, &entropy_context);

    initialize_ecdh_context(&Alice_context);
    initialize_ecdh_context(&Bob_context);

    generate_keypair(&Alice_context, &random_context);
    generate_keypair(&Bob_context, &random_context);

    compute_shared_secret(&Alice_context, &Bob_context.private_Q, &Alice_context.private_d, &random_context);
    compute_shared_secret(&Bob_context, &Alice_context.private_Q, &Bob_context.private_d, &random_context);

    compare_shared_secrets(&Alice_context.private_z, &Bob_context.private_z);

    for (;;);
}
