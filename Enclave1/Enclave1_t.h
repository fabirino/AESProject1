#ifndef ENCLAVE1_T_H__
#define ENCLAVE1_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t e1_get_sealed_data_size(uint32_t data_size);
uint32_t e1_get_unsealed_data_size(unsigned char* sealed_data, uint32_t sealed_data_size);
void e1_create_tpdv(unsigned char* autor, unsigned char* password, size_t author_len, size_t password_len, unsigned char* sealed_data, uint32_t sealed_data_size);
void e1_add_asset(unsigned char* tpdv_data, unsigned char* autor, unsigned char* password, unsigned char* asset_name, unsigned char* asset, uint32_t tpdv_data_size_unsealed, uint32_t tpdv_data_size, size_t author_len, size_t password_len, size_t asset_name_len, uint32_t asset_size, unsigned char* sealed_data, uint32_t sealed_data_size);
void e1_list_assets(unsigned char* file_name, unsigned char* sealed_data, unsigned char* author, unsigned char* password, size_t file_name_len, uint32_t sealed_data_size, size_t author_len, size_t password_len);
uint32_t e1_get_asset_size(unsigned char* seal_data, int indice, uint32_t tpdv_data_size);
void e1_extract_asset(unsigned char* sealed_data, unsigned char* author, unsigned char* password, int indice, uint32_t sealed_data_size, size_t author_len, size_t password_len, unsigned char* unsealed_data, unsigned char* asset_name, uint32_t asset_size, size_t asset_name_len);
void e1_compare_hash(unsigned char* sealed_data, unsigned char* author, unsigned char* password, int indice, unsigned char* hash, uint32_t sealed_data_size, size_t AUTHOR_SIZE, size_t PW_SIZE, size_t hash_size);
void e1_change_password(unsigned char* tpdv_data, unsigned char* author, unsigned char* password, unsigned char* new_password, uint32_t tpdv_data_size, size_t author_len, size_t password_len, size_t new_password_len, unsigned char* sealed_data, uint32_t sealed_data_size);

sgx_status_t SGX_CDECL ocall_e1_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
