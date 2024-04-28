#include "Enclave1_u.h"
#include <errno.h>

typedef struct ms_e1_get_sealed_data_size_t {
	uint32_t ms_retval;
	uint32_t ms_data_size;
} ms_e1_get_sealed_data_size_t;

typedef struct ms_e1_get_unsealed_data_size_t {
	uint32_t ms_retval;
	unsigned char* ms_sealed_data;
	uint32_t ms_sealed_data_size;
} ms_e1_get_unsealed_data_size_t;

typedef struct ms_e1_create_tpdv_t {
	unsigned char* ms_autor;
	unsigned char* ms_password;
	size_t ms_author_len;
	size_t ms_password_len;
	unsigned char* ms_sealed_data;
	uint32_t ms_sealed_data_size;
} ms_e1_create_tpdv_t;

typedef struct ms_e1_add_asset_t {
	unsigned char* ms_tpdv_data;
	unsigned char* ms_autor;
	unsigned char* ms_password;
	unsigned char* ms_asset_name;
	unsigned char* ms_asset;
	uint32_t ms_tpdv_data_size_unsealed;
	uint32_t ms_tpdv_data_size;
	size_t ms_author_len;
	size_t ms_password_len;
	size_t ms_asset_name_len;
	uint32_t ms_asset_size;
	unsigned char* ms_sealed_data;
	uint32_t ms_sealed_data_size;
} ms_e1_add_asset_t;

typedef struct ms_e1_list_assets_t {
	unsigned char* ms_file_name;
	unsigned char* ms_sealed_data;
	unsigned char* ms_author;
	unsigned char* ms_password;
	size_t ms_file_name_len;
	uint32_t ms_sealed_data_size;
	size_t ms_author_len;
	size_t ms_password_len;
} ms_e1_list_assets_t;

typedef struct ms_e1_extract_asset_t {
	unsigned char* ms_file_name;
	unsigned char* ms_author;
	unsigned char* ms_password;
	int ms_indice;
	size_t ms_file_name_len;
	size_t ms_author_len;
	size_t ms_password_len;
} ms_e1_extract_asset_t;

typedef struct ms_e1_compare_hash_t {
	unsigned char* ms_file_name;
	unsigned char* ms_author;
	unsigned char* ms_password;
	int ms_indice;
	unsigned char* ms_hash;
	int ms_hash_type;
	size_t ms_FILE_NAME_SIZE;
	size_t ms_AUTHOR_SIZE;
	size_t ms_PW_SIZE;
	size_t ms_hash_size;
} ms_e1_compare_hash_t;

typedef struct ms_ocall_e1_print_string_t {
	const char* ms_str;
} ms_ocall_e1_print_string_t;

static sgx_status_t SGX_CDECL Enclave1_ocall_e1_print_string(void* pms)
{
	ms_ocall_e1_print_string_t* ms = SGX_CAST(ms_ocall_e1_print_string_t*, pms);
	ocall_e1_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave1 = {
	1,
	{
		(void*)Enclave1_ocall_e1_print_string,
	}
};
sgx_status_t e1_get_sealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, uint32_t data_size)
{
	sgx_status_t status;
	ms_e1_get_sealed_data_size_t ms;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave1, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e1_get_unsealed_data_size(sgx_enclave_id_t eid, uint32_t* retval, unsigned char* sealed_data, uint32_t sealed_data_size)
{
	sgx_status_t status;
	ms_e1_get_unsealed_data_size_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_data_size = sealed_data_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave1, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e1_create_tpdv(sgx_enclave_id_t eid, unsigned char* autor, unsigned char* password, size_t author_len, size_t password_len, unsigned char* sealed_data, uint32_t sealed_data_size)
{
	sgx_status_t status;
	ms_e1_create_tpdv_t ms;
	ms.ms_autor = autor;
	ms.ms_password = password;
	ms.ms_author_len = author_len;
	ms.ms_password_len = password_len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_data_size = sealed_data_size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t e1_add_asset(sgx_enclave_id_t eid, unsigned char* tpdv_data, unsigned char* autor, unsigned char* password, unsigned char* asset_name, unsigned char* asset, uint32_t tpdv_data_size_unsealed, uint32_t tpdv_data_size, size_t author_len, size_t password_len, size_t asset_name_len, uint32_t asset_size, unsigned char* sealed_data, uint32_t sealed_data_size)
{
	sgx_status_t status;
	ms_e1_add_asset_t ms;
	ms.ms_tpdv_data = tpdv_data;
	ms.ms_autor = autor;
	ms.ms_password = password;
	ms.ms_asset_name = asset_name;
	ms.ms_asset = asset;
	ms.ms_tpdv_data_size_unsealed = tpdv_data_size_unsealed;
	ms.ms_tpdv_data_size = tpdv_data_size;
	ms.ms_author_len = author_len;
	ms.ms_password_len = password_len;
	ms.ms_asset_name_len = asset_name_len;
	ms.ms_asset_size = asset_size;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_data_size = sealed_data_size;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t e1_list_assets(sgx_enclave_id_t eid, unsigned char* file_name, unsigned char* sealed_data, unsigned char* author, unsigned char* password, size_t file_name_len, uint32_t sealed_data_size, size_t author_len, size_t password_len)
{
	sgx_status_t status;
	ms_e1_list_assets_t ms;
	ms.ms_file_name = file_name;
	ms.ms_sealed_data = sealed_data;
	ms.ms_author = author;
	ms.ms_password = password;
	ms.ms_file_name_len = file_name_len;
	ms.ms_sealed_data_size = sealed_data_size;
	ms.ms_author_len = author_len;
	ms.ms_password_len = password_len;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t e1_extract_asset(sgx_enclave_id_t eid, unsigned char* file_name, unsigned char* author, unsigned char* password, int indice, size_t file_name_len, size_t author_len, size_t password_len)
{
	sgx_status_t status;
	ms_e1_extract_asset_t ms;
	ms.ms_file_name = file_name;
	ms.ms_author = author;
	ms.ms_password = password;
	ms.ms_indice = indice;
	ms.ms_file_name_len = file_name_len;
	ms.ms_author_len = author_len;
	ms.ms_password_len = password_len;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t e1_compare_hash(sgx_enclave_id_t eid, unsigned char* file_name, unsigned char* author, unsigned char* password, int indice, unsigned char* hash, int hash_type, size_t FILE_NAME_SIZE, size_t AUTHOR_SIZE, size_t PW_SIZE, size_t hash_size)
{
	sgx_status_t status;
	ms_e1_compare_hash_t ms;
	ms.ms_file_name = file_name;
	ms.ms_author = author;
	ms.ms_password = password;
	ms.ms_indice = indice;
	ms.ms_hash = hash;
	ms.ms_hash_type = hash_type;
	ms.ms_FILE_NAME_SIZE = FILE_NAME_SIZE;
	ms.ms_AUTHOR_SIZE = AUTHOR_SIZE;
	ms.ms_PW_SIZE = PW_SIZE;
	ms.ms_hash_size = hash_size;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave1, &ms);
	return status;
}

