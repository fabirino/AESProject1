#ifndef ENCLAVE1_U_H__
#define ENCLAVE1_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_E1_PRINT_STRING_DEFINED__
#define OCALL_E1_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_e1_print_string, (const char* str));
#endif

sgx_status_t e1_get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, uint32_t data_size);
sgx_status_t e1_get_unsealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, unsigned char* sealed_data, uint32_t sealed_data_size);
sgx_status_t e1_create_tpdv(sgx_enclave_id_t eid, unsigned char* autor, unsigned char* password, size_t author_len, size_t password_len, unsigned char* sealed_data, uint32_t sealed_data_size);
sgx_status_t e1_add_asset(sgx_enclave_id_t eid, unsigned char* tpdv_data, unsigned char* autor, unsigned char* password, unsigned char* asset_name, unsigned char* asset, uint32_t tpdv_data_size_unsealed, uint32_t tpdv_data_size, size_t author_len, size_t password_len, size_t asset_name_len, uint32_t asset_size, unsigned char* sealed_data, uint32_t sealed_data_size);
sgx_status_t e1_list_assets(sgx_enclave_id_t eid, unsigned char* sealed_data, unsigned char* author, unsigned char* password, uint32_t sealed_data_size, size_t author_len, size_t password_len);
sgx_status_t e1_extract_asset(sgx_enclave_id_t eid, unsigned char* file_name, unsigned char* author, unsigned char* password, int indice, size_t file_name_len, size_t author_len, size_t password_len);
sgx_status_t e1_compare_hash(sgx_enclave_id_t eid, unsigned char* file_name, unsigned char* author, unsigned char* password, int indice, unsigned char* hash, int hash_type, size_t FILE_NAME_SIZE, size_t AUTHOR_SIZE, size_t PW_SIZE, size_t hash_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
