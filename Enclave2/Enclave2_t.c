#include "Enclave2_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_e2_get_sealed_data_size_t {
	uint32_t ms_retval;
	uint32_t ms_data_size;
} ms_e2_get_sealed_data_size_t;

typedef struct ms_e2_get_unsealed_data_size_t {
	uint32_t ms_retval;
	unsigned char* ms_sealed_data;
	uint32_t ms_sealed_data_size;
} ms_e2_get_unsealed_data_size_t;

typedef struct ms_e2_create_tpdv_t {
	unsigned char* ms_autor;
	unsigned char* ms_password;
	size_t ms_author_len;
	size_t ms_password_len;
	unsigned char* ms_sealed_data;
	uint32_t ms_sealed_data_size;
} ms_e2_create_tpdv_t;

typedef struct ms_e2_add_asset_t {
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
} ms_e2_add_asset_t;

typedef struct ms_e2_list_assets_t {
	unsigned char* ms_file_name;
	unsigned char* ms_sealed_data;
	unsigned char* ms_author;
	unsigned char* ms_password;
	size_t ms_file_name_len;
	uint32_t ms_sealed_data_size;
	size_t ms_author_len;
	size_t ms_password_len;
} ms_e2_list_assets_t;

typedef struct ms_e2_get_asset_size_t {
	uint32_t ms_retval;
	unsigned char* ms_seal_data;
	int ms_indice;
	uint32_t ms_tpdv_data_size;
} ms_e2_get_asset_size_t;

typedef struct ms_e2_extract_asset_t {
	unsigned char* ms_sealed_data;
	unsigned char* ms_author;
	unsigned char* ms_password;
	int ms_indice;
	uint32_t ms_sealed_data_size;
	size_t ms_author_len;
	size_t ms_password_len;
	unsigned char* ms_unsealed_data;
	unsigned char* ms_asset_name;
	uint32_t ms_asset_size;
	size_t ms_asset_name_len;
} ms_e2_extract_asset_t;

typedef struct ms_e2_compare_hash_t {
	unsigned char* ms_sealed_data;
	unsigned char* ms_author;
	unsigned char* ms_password;
	int ms_indice;
	unsigned char* ms_hash;
	uint32_t ms_sealed_data_size;
	size_t ms_AUTHOR_SIZE;
	size_t ms_PW_SIZE;
	size_t ms_hash_size;
} ms_e2_compare_hash_t;

typedef struct ms_e2_change_password_t {
	unsigned char* ms_tpdv_data;
	unsigned char* ms_author;
	unsigned char* ms_password;
	unsigned char* ms_new_password;
	uint32_t ms_tpdv_data_size;
	size_t ms_author_len;
	size_t ms_password_len;
	size_t ms_new_password_len;
	unsigned char* ms_sealed_data;
	uint32_t ms_sealed_data_size;
} ms_e2_change_password_t;

typedef struct ms_e2_init_session_t {
	sgx_status_t* ms_dh_status;
} ms_e2_init_session_t;

typedef struct ms_e2_create_message1_t {
	sgx_dh_msg1_t* ms_msg1;
	sgx_status_t* ms_dh_status;
} ms_e2_create_message1_t;

typedef struct ms_e2_process_message2_t {
	const sgx_dh_msg2_t* ms_msg2;
	sgx_dh_msg3_t* ms_msg3;
	sgx_status_t* ms_dh_status;
} ms_e2_process_message2_t;

typedef struct ms_e2_seal_ciphertext_t {
	unsigned char* ms_ciphertext;
	uint32_t ms_ciphertext_size;
	unsigned char* ms_selead_data;
	uint32_t ms_sealed_data_size;
} ms_e2_seal_ciphertext_t;

typedef struct ms_ocall_e2_print_string_t {
	const char* ms_str;
} ms_ocall_e2_print_string_t;

static sgx_status_t SGX_CDECL sgx_e2_get_sealed_data_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_get_sealed_data_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_get_sealed_data_size_t* ms = SGX_CAST(ms_e2_get_sealed_data_size_t*, pms);
	ms_e2_get_sealed_data_size_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_get_sealed_data_size_t), ms, sizeof(ms_e2_get_sealed_data_size_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint32_t _in_retval;


	_in_retval = e2_get_sealed_data_size(__in_ms.ms_data_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_get_unsealed_data_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_get_unsealed_data_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_get_unsealed_data_size_t* ms = SGX_CAST(ms_e2_get_unsealed_data_size_t*, pms);
	ms_e2_get_unsealed_data_size_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_get_unsealed_data_size_t), ms, sizeof(ms_e2_get_unsealed_data_size_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_data_size = __in_ms.ms_sealed_data_size;
	size_t _len_sealed_data = _tmp_sealed_data_size;
	unsigned char* _in_sealed_data = NULL;
	uint32_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_data = (unsigned char*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = e2_get_unsealed_data_size(_in_sealed_data, _tmp_sealed_data_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_create_tpdv(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_create_tpdv_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_create_tpdv_t* ms = SGX_CAST(ms_e2_create_tpdv_t*, pms);
	ms_e2_create_tpdv_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_create_tpdv_t), ms, sizeof(ms_e2_create_tpdv_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_autor = __in_ms.ms_autor;
	size_t _tmp_author_len = __in_ms.ms_author_len;
	size_t _len_autor = _tmp_author_len;
	unsigned char* _in_autor = NULL;
	unsigned char* _tmp_password = __in_ms.ms_password;
	size_t _tmp_password_len = __in_ms.ms_password_len;
	size_t _len_password = _tmp_password_len;
	unsigned char* _in_password = NULL;
	unsigned char* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_data_size = __in_ms.ms_sealed_data_size;
	size_t _len_sealed_data = _tmp_sealed_data_size;
	unsigned char* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_autor, _len_autor);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_autor != NULL && _len_autor != 0) {
		if ( _len_autor % sizeof(*_tmp_autor) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_autor = (unsigned char*)malloc(_len_autor);
		if (_in_autor == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_autor, _len_autor, _tmp_autor, _len_autor)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_password != NULL && _len_password != 0) {
		if ( _len_password % sizeof(*_tmp_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_password = (unsigned char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_data = (unsigned char*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	e2_create_tpdv(_in_autor, _in_password, _tmp_author_len, _tmp_password_len, _in_sealed_data, _tmp_sealed_data_size);
	if (_in_sealed_data) {
		if (memcpy_verw_s(_tmp_sealed_data, _len_sealed_data, _in_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_autor) free(_in_autor);
	if (_in_password) free(_in_password);
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_add_asset(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_add_asset_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_add_asset_t* ms = SGX_CAST(ms_e2_add_asset_t*, pms);
	ms_e2_add_asset_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_add_asset_t), ms, sizeof(ms_e2_add_asset_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_tpdv_data = __in_ms.ms_tpdv_data;
	uint32_t _tmp_tpdv_data_size = __in_ms.ms_tpdv_data_size;
	size_t _len_tpdv_data = _tmp_tpdv_data_size;
	unsigned char* _in_tpdv_data = NULL;
	unsigned char* _tmp_autor = __in_ms.ms_autor;
	size_t _tmp_author_len = __in_ms.ms_author_len;
	size_t _len_autor = _tmp_author_len;
	unsigned char* _in_autor = NULL;
	unsigned char* _tmp_password = __in_ms.ms_password;
	size_t _tmp_password_len = __in_ms.ms_password_len;
	size_t _len_password = _tmp_password_len;
	unsigned char* _in_password = NULL;
	unsigned char* _tmp_asset_name = __in_ms.ms_asset_name;
	size_t _tmp_asset_name_len = __in_ms.ms_asset_name_len;
	size_t _len_asset_name = _tmp_asset_name_len;
	unsigned char* _in_asset_name = NULL;
	unsigned char* _tmp_asset = __in_ms.ms_asset;
	uint32_t _tmp_asset_size = __in_ms.ms_asset_size;
	size_t _len_asset = _tmp_asset_size;
	unsigned char* _in_asset = NULL;
	unsigned char* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_data_size = __in_ms.ms_sealed_data_size;
	size_t _len_sealed_data = _tmp_sealed_data_size;
	unsigned char* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_tpdv_data, _len_tpdv_data);
	CHECK_UNIQUE_POINTER(_tmp_autor, _len_autor);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);
	CHECK_UNIQUE_POINTER(_tmp_asset_name, _len_asset_name);
	CHECK_UNIQUE_POINTER(_tmp_asset, _len_asset);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_tpdv_data != NULL && _len_tpdv_data != 0) {
		if ( _len_tpdv_data % sizeof(*_tmp_tpdv_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tpdv_data = (unsigned char*)malloc(_len_tpdv_data);
		if (_in_tpdv_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tpdv_data, _len_tpdv_data, _tmp_tpdv_data, _len_tpdv_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_autor != NULL && _len_autor != 0) {
		if ( _len_autor % sizeof(*_tmp_autor) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_autor = (unsigned char*)malloc(_len_autor);
		if (_in_autor == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_autor, _len_autor, _tmp_autor, _len_autor)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_password != NULL && _len_password != 0) {
		if ( _len_password % sizeof(*_tmp_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_password = (unsigned char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_asset_name != NULL && _len_asset_name != 0) {
		if ( _len_asset_name % sizeof(*_tmp_asset_name) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_asset_name = (unsigned char*)malloc(_len_asset_name);
		if (_in_asset_name == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_asset_name, _len_asset_name, _tmp_asset_name, _len_asset_name)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_asset != NULL && _len_asset != 0) {
		if ( _len_asset % sizeof(*_tmp_asset) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_asset = (unsigned char*)malloc(_len_asset);
		if (_in_asset == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_asset, _len_asset, _tmp_asset, _len_asset)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_data = (unsigned char*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	e2_add_asset(_in_tpdv_data, _in_autor, _in_password, _in_asset_name, _in_asset, __in_ms.ms_tpdv_data_size_unsealed, _tmp_tpdv_data_size, _tmp_author_len, _tmp_password_len, _tmp_asset_name_len, _tmp_asset_size, _in_sealed_data, _tmp_sealed_data_size);
	if (_in_sealed_data) {
		if (memcpy_verw_s(_tmp_sealed_data, _len_sealed_data, _in_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_tpdv_data) free(_in_tpdv_data);
	if (_in_autor) free(_in_autor);
	if (_in_password) free(_in_password);
	if (_in_asset_name) free(_in_asset_name);
	if (_in_asset) free(_in_asset);
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_list_assets(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_list_assets_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_list_assets_t* ms = SGX_CAST(ms_e2_list_assets_t*, pms);
	ms_e2_list_assets_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_list_assets_t), ms, sizeof(ms_e2_list_assets_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_file_name = __in_ms.ms_file_name;
	size_t _tmp_file_name_len = __in_ms.ms_file_name_len;
	size_t _len_file_name = _tmp_file_name_len;
	unsigned char* _in_file_name = NULL;
	unsigned char* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_data_size = __in_ms.ms_sealed_data_size;
	size_t _len_sealed_data = _tmp_sealed_data_size;
	unsigned char* _in_sealed_data = NULL;
	unsigned char* _tmp_author = __in_ms.ms_author;
	size_t _tmp_author_len = __in_ms.ms_author_len;
	size_t _len_author = _tmp_author_len;
	unsigned char* _in_author = NULL;
	unsigned char* _tmp_password = __in_ms.ms_password;
	size_t _tmp_password_len = __in_ms.ms_password_len;
	size_t _len_password = _tmp_password_len;
	unsigned char* _in_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_file_name, _len_file_name);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_author, _len_author);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_file_name != NULL && _len_file_name != 0) {
		if ( _len_file_name % sizeof(*_tmp_file_name) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_file_name = (unsigned char*)malloc(_len_file_name);
		if (_in_file_name == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_file_name, _len_file_name, _tmp_file_name, _len_file_name)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_data = (unsigned char*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_author != NULL && _len_author != 0) {
		if ( _len_author % sizeof(*_tmp_author) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_author = (unsigned char*)malloc(_len_author);
		if (_in_author == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_author, _len_author, _tmp_author, _len_author)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_password != NULL && _len_password != 0) {
		if ( _len_password % sizeof(*_tmp_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_password = (unsigned char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	e2_list_assets(_in_file_name, _in_sealed_data, _in_author, _in_password, _tmp_file_name_len, _tmp_sealed_data_size, _tmp_author_len, _tmp_password_len);

err:
	if (_in_file_name) free(_in_file_name);
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_author) free(_in_author);
	if (_in_password) free(_in_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_get_asset_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_get_asset_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_get_asset_size_t* ms = SGX_CAST(ms_e2_get_asset_size_t*, pms);
	ms_e2_get_asset_size_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_get_asset_size_t), ms, sizeof(ms_e2_get_asset_size_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_seal_data = __in_ms.ms_seal_data;
	uint32_t _tmp_tpdv_data_size = __in_ms.ms_tpdv_data_size;
	size_t _len_seal_data = _tmp_tpdv_data_size;
	unsigned char* _in_seal_data = NULL;
	uint32_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_seal_data, _len_seal_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_seal_data != NULL && _len_seal_data != 0) {
		if ( _len_seal_data % sizeof(*_tmp_seal_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_seal_data = (unsigned char*)malloc(_len_seal_data);
		if (_in_seal_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_seal_data, _len_seal_data, _tmp_seal_data, _len_seal_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = e2_get_asset_size(_in_seal_data, __in_ms.ms_indice, _tmp_tpdv_data_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_seal_data) free(_in_seal_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_extract_asset(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_extract_asset_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_extract_asset_t* ms = SGX_CAST(ms_e2_extract_asset_t*, pms);
	ms_e2_extract_asset_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_extract_asset_t), ms, sizeof(ms_e2_extract_asset_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_data_size = __in_ms.ms_sealed_data_size;
	size_t _len_sealed_data = _tmp_sealed_data_size;
	unsigned char* _in_sealed_data = NULL;
	unsigned char* _tmp_author = __in_ms.ms_author;
	size_t _tmp_author_len = __in_ms.ms_author_len;
	size_t _len_author = _tmp_author_len;
	unsigned char* _in_author = NULL;
	unsigned char* _tmp_password = __in_ms.ms_password;
	size_t _tmp_password_len = __in_ms.ms_password_len;
	size_t _len_password = _tmp_password_len;
	unsigned char* _in_password = NULL;
	unsigned char* _tmp_unsealed_data = __in_ms.ms_unsealed_data;
	uint32_t _tmp_asset_size = __in_ms.ms_asset_size;
	size_t _len_unsealed_data = _tmp_asset_size;
	unsigned char* _in_unsealed_data = NULL;
	unsigned char* _tmp_asset_name = __in_ms.ms_asset_name;
	size_t _tmp_asset_name_len = __in_ms.ms_asset_name_len;
	size_t _len_asset_name = _tmp_asset_name_len;
	unsigned char* _in_asset_name = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_author, _len_author);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);
	CHECK_UNIQUE_POINTER(_tmp_unsealed_data, _len_unsealed_data);
	CHECK_UNIQUE_POINTER(_tmp_asset_name, _len_asset_name);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_data = (unsigned char*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_author != NULL && _len_author != 0) {
		if ( _len_author % sizeof(*_tmp_author) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_author = (unsigned char*)malloc(_len_author);
		if (_in_author == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_author, _len_author, _tmp_author, _len_author)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_password != NULL && _len_password != 0) {
		if ( _len_password % sizeof(*_tmp_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_password = (unsigned char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_unsealed_data != NULL && _len_unsealed_data != 0) {
		if ( _len_unsealed_data % sizeof(*_tmp_unsealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_unsealed_data = (unsigned char*)malloc(_len_unsealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_unsealed_data, 0, _len_unsealed_data);
	}
	if (_tmp_asset_name != NULL && _len_asset_name != 0) {
		if ( _len_asset_name % sizeof(*_tmp_asset_name) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_asset_name = (unsigned char*)malloc(_len_asset_name)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_asset_name, 0, _len_asset_name);
	}
	e2_extract_asset(_in_sealed_data, _in_author, _in_password, __in_ms.ms_indice, _tmp_sealed_data_size, _tmp_author_len, _tmp_password_len, _in_unsealed_data, _in_asset_name, _tmp_asset_size, _tmp_asset_name_len);
	if (_in_unsealed_data) {
		if (memcpy_verw_s(_tmp_unsealed_data, _len_unsealed_data, _in_unsealed_data, _len_unsealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_asset_name) {
		if (memcpy_verw_s(_tmp_asset_name, _len_asset_name, _in_asset_name, _len_asset_name)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_author) free(_in_author);
	if (_in_password) free(_in_password);
	if (_in_unsealed_data) free(_in_unsealed_data);
	if (_in_asset_name) free(_in_asset_name);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_compare_hash(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_compare_hash_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_compare_hash_t* ms = SGX_CAST(ms_e2_compare_hash_t*, pms);
	ms_e2_compare_hash_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_compare_hash_t), ms, sizeof(ms_e2_compare_hash_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_data_size = __in_ms.ms_sealed_data_size;
	size_t _len_sealed_data = _tmp_sealed_data_size;
	unsigned char* _in_sealed_data = NULL;
	unsigned char* _tmp_author = __in_ms.ms_author;
	size_t _tmp_AUTHOR_SIZE = __in_ms.ms_AUTHOR_SIZE;
	size_t _len_author = _tmp_AUTHOR_SIZE;
	unsigned char* _in_author = NULL;
	unsigned char* _tmp_password = __in_ms.ms_password;
	size_t _tmp_PW_SIZE = __in_ms.ms_PW_SIZE;
	size_t _len_password = _tmp_PW_SIZE;
	unsigned char* _in_password = NULL;
	unsigned char* _tmp_hash = __in_ms.ms_hash;
	size_t _tmp_hash_size = __in_ms.ms_hash_size;
	size_t _len_hash = _tmp_hash_size;
	unsigned char* _in_hash = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_author, _len_author);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);
	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_data = (unsigned char*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_author != NULL && _len_author != 0) {
		if ( _len_author % sizeof(*_tmp_author) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_author = (unsigned char*)malloc(_len_author);
		if (_in_author == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_author, _len_author, _tmp_author, _len_author)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_password != NULL && _len_password != 0) {
		if ( _len_password % sizeof(*_tmp_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_password = (unsigned char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_hash != NULL && _len_hash != 0) {
		if ( _len_hash % sizeof(*_tmp_hash) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_hash = (unsigned char*)malloc(_len_hash);
		if (_in_hash == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_hash, _len_hash, _tmp_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	e2_compare_hash(_in_sealed_data, _in_author, _in_password, __in_ms.ms_indice, _in_hash, _tmp_sealed_data_size, _tmp_AUTHOR_SIZE, _tmp_PW_SIZE, _tmp_hash_size);

err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_author) free(_in_author);
	if (_in_password) free(_in_password);
	if (_in_hash) free(_in_hash);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_change_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_change_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_change_password_t* ms = SGX_CAST(ms_e2_change_password_t*, pms);
	ms_e2_change_password_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_change_password_t), ms, sizeof(ms_e2_change_password_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_tpdv_data = __in_ms.ms_tpdv_data;
	uint32_t _tmp_tpdv_data_size = __in_ms.ms_tpdv_data_size;
	size_t _len_tpdv_data = _tmp_tpdv_data_size;
	unsigned char* _in_tpdv_data = NULL;
	unsigned char* _tmp_author = __in_ms.ms_author;
	size_t _tmp_author_len = __in_ms.ms_author_len;
	size_t _len_author = _tmp_author_len;
	unsigned char* _in_author = NULL;
	unsigned char* _tmp_password = __in_ms.ms_password;
	size_t _tmp_password_len = __in_ms.ms_password_len;
	size_t _len_password = _tmp_password_len;
	unsigned char* _in_password = NULL;
	unsigned char* _tmp_new_password = __in_ms.ms_new_password;
	size_t _tmp_new_password_len = __in_ms.ms_new_password_len;
	size_t _len_new_password = _tmp_new_password_len;
	unsigned char* _in_new_password = NULL;
	unsigned char* _tmp_sealed_data = __in_ms.ms_sealed_data;
	uint32_t _tmp_sealed_data_size = __in_ms.ms_sealed_data_size;
	size_t _len_sealed_data = _tmp_sealed_data_size;
	unsigned char* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_tpdv_data, _len_tpdv_data);
	CHECK_UNIQUE_POINTER(_tmp_author, _len_author);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);
	CHECK_UNIQUE_POINTER(_tmp_new_password, _len_new_password);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_tpdv_data != NULL && _len_tpdv_data != 0) {
		if ( _len_tpdv_data % sizeof(*_tmp_tpdv_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_tpdv_data = (unsigned char*)malloc(_len_tpdv_data);
		if (_in_tpdv_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tpdv_data, _len_tpdv_data, _tmp_tpdv_data, _len_tpdv_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_author != NULL && _len_author != 0) {
		if ( _len_author % sizeof(*_tmp_author) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_author = (unsigned char*)malloc(_len_author);
		if (_in_author == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_author, _len_author, _tmp_author, _len_author)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_password != NULL && _len_password != 0) {
		if ( _len_password % sizeof(*_tmp_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_password = (unsigned char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_new_password != NULL && _len_new_password != 0) {
		if ( _len_new_password % sizeof(*_tmp_new_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_new_password = (unsigned char*)malloc(_len_new_password);
		if (_in_new_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_new_password, _len_new_password, _tmp_new_password, _len_new_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_data = (unsigned char*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	e2_change_password(_in_tpdv_data, _in_author, _in_password, _in_new_password, _tmp_tpdv_data_size, _tmp_author_len, _tmp_password_len, _tmp_new_password_len, _in_sealed_data, _tmp_sealed_data_size);
	if (_in_sealed_data) {
		if (memcpy_verw_s(_tmp_sealed_data, _len_sealed_data, _in_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_tpdv_data) free(_in_tpdv_data);
	if (_in_author) free(_in_author);
	if (_in_password) free(_in_password);
	if (_in_new_password) free(_in_new_password);
	if (_in_sealed_data) free(_in_sealed_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_init_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_init_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_init_session_t* ms = SGX_CAST(ms_e2_init_session_t*, pms);
	ms_e2_init_session_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_init_session_t), ms, sizeof(ms_e2_init_session_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t* _tmp_dh_status = __in_ms.ms_dh_status;
	size_t _len_dh_status = sizeof(sgx_status_t);
	sgx_status_t* _in_dh_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_dh_status, _len_dh_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dh_status != NULL && _len_dh_status != 0) {
		if ((_in_dh_status = (sgx_status_t*)malloc(_len_dh_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_status, 0, _len_dh_status);
	}
	e2_init_session(_in_dh_status);
	if (_in_dh_status) {
		if (memcpy_verw_s(_tmp_dh_status, _len_dh_status, _in_dh_status, _len_dh_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_dh_status) free(_in_dh_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_create_message1(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_create_message1_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_create_message1_t* ms = SGX_CAST(ms_e2_create_message1_t*, pms);
	ms_e2_create_message1_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_create_message1_t), ms, sizeof(ms_e2_create_message1_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_msg1_t* _tmp_msg1 = __in_ms.ms_msg1;
	size_t _len_msg1 = sizeof(sgx_dh_msg1_t);
	sgx_dh_msg1_t* _in_msg1 = NULL;
	sgx_status_t* _tmp_dh_status = __in_ms.ms_dh_status;
	size_t _len_dh_status = sizeof(sgx_status_t);
	sgx_status_t* _in_dh_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_msg1, _len_msg1);
	CHECK_UNIQUE_POINTER(_tmp_dh_status, _len_dh_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_msg1 != NULL && _len_msg1 != 0) {
		if ((_in_msg1 = (sgx_dh_msg1_t*)malloc(_len_msg1)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_msg1, 0, _len_msg1);
	}
	if (_tmp_dh_status != NULL && _len_dh_status != 0) {
		if ((_in_dh_status = (sgx_status_t*)malloc(_len_dh_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_status, 0, _len_dh_status);
	}
	e2_create_message1(_in_msg1, _in_dh_status);
	if (_in_msg1) {
		if (memcpy_verw_s(_tmp_msg1, _len_msg1, _in_msg1, _len_msg1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_dh_status) {
		if (memcpy_verw_s(_tmp_dh_status, _len_dh_status, _in_dh_status, _len_dh_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_msg1) free(_in_msg1);
	if (_in_dh_status) free(_in_dh_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_process_message2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_process_message2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_process_message2_t* ms = SGX_CAST(ms_e2_process_message2_t*, pms);
	ms_e2_process_message2_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_process_message2_t), ms, sizeof(ms_e2_process_message2_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_dh_msg2_t* _tmp_msg2 = __in_ms.ms_msg2;
	size_t _len_msg2 = sizeof(sgx_dh_msg2_t);
	sgx_dh_msg2_t* _in_msg2 = NULL;
	sgx_dh_msg3_t* _tmp_msg3 = __in_ms.ms_msg3;
	size_t _len_msg3 = sizeof(sgx_dh_msg3_t);
	sgx_dh_msg3_t* _in_msg3 = NULL;
	sgx_status_t* _tmp_dh_status = __in_ms.ms_dh_status;
	size_t _len_dh_status = sizeof(sgx_status_t);
	sgx_status_t* _in_dh_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_msg2, _len_msg2);
	CHECK_UNIQUE_POINTER(_tmp_msg3, _len_msg3);
	CHECK_UNIQUE_POINTER(_tmp_dh_status, _len_dh_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_msg2 != NULL && _len_msg2 != 0) {
		_in_msg2 = (sgx_dh_msg2_t*)malloc(_len_msg2);
		if (_in_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg2, _len_msg2, _tmp_msg2, _len_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_msg3 != NULL && _len_msg3 != 0) {
		if ((_in_msg3 = (sgx_dh_msg3_t*)malloc(_len_msg3)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_msg3, 0, _len_msg3);
	}
	if (_tmp_dh_status != NULL && _len_dh_status != 0) {
		if ((_in_dh_status = (sgx_status_t*)malloc(_len_dh_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_status, 0, _len_dh_status);
	}
	e2_process_message2((const sgx_dh_msg2_t*)_in_msg2, _in_msg3, _in_dh_status);
	if (_in_msg3) {
		if (memcpy_verw_s(_tmp_msg3, _len_msg3, _in_msg3, _len_msg3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_dh_status) {
		if (memcpy_verw_s(_tmp_dh_status, _len_dh_status, _in_dh_status, _len_dh_status)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_msg2) free(_in_msg2);
	if (_in_msg3) free(_in_msg3);
	if (_in_dh_status) free(_in_dh_status);
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_show_secret_key(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	e2_show_secret_key();
	return status;
}

static sgx_status_t SGX_CDECL sgx_e2_seal_ciphertext(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_e2_seal_ciphertext_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_e2_seal_ciphertext_t* ms = SGX_CAST(ms_e2_seal_ciphertext_t*, pms);
	ms_e2_seal_ciphertext_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_e2_seal_ciphertext_t), ms, sizeof(ms_e2_seal_ciphertext_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_ciphertext = __in_ms.ms_ciphertext;
	uint32_t _tmp_ciphertext_size = __in_ms.ms_ciphertext_size;
	size_t _len_ciphertext = _tmp_ciphertext_size;
	unsigned char* _in_ciphertext = NULL;
	unsigned char* _tmp_selead_data = __in_ms.ms_selead_data;
	uint32_t _tmp_sealed_data_size = __in_ms.ms_sealed_data_size;
	size_t _len_selead_data = _tmp_sealed_data_size;
	unsigned char* _in_selead_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ciphertext, _len_ciphertext);
	CHECK_UNIQUE_POINTER(_tmp_selead_data, _len_selead_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ciphertext != NULL && _len_ciphertext != 0) {
		if ( _len_ciphertext % sizeof(*_tmp_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ciphertext = (unsigned char*)malloc(_len_ciphertext);
		if (_in_ciphertext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ciphertext, _len_ciphertext, _tmp_ciphertext, _len_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_selead_data != NULL && _len_selead_data != 0) {
		if ( _len_selead_data % sizeof(*_tmp_selead_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_selead_data = (unsigned char*)malloc(_len_selead_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_selead_data, 0, _len_selead_data);
	}
	e2_seal_ciphertext(_in_ciphertext, _tmp_ciphertext_size, _in_selead_data, _tmp_sealed_data_size);
	if (_in_selead_data) {
		if (memcpy_verw_s(_tmp_selead_data, _len_selead_data, _in_selead_data, _len_selead_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ciphertext) free(_in_ciphertext);
	if (_in_selead_data) free(_in_selead_data);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[14];
} g_ecall_table = {
	14,
	{
		{(void*)(uintptr_t)sgx_e2_get_sealed_data_size, 0, 0},
		{(void*)(uintptr_t)sgx_e2_get_unsealed_data_size, 0, 0},
		{(void*)(uintptr_t)sgx_e2_create_tpdv, 0, 0},
		{(void*)(uintptr_t)sgx_e2_add_asset, 0, 0},
		{(void*)(uintptr_t)sgx_e2_list_assets, 0, 0},
		{(void*)(uintptr_t)sgx_e2_get_asset_size, 0, 0},
		{(void*)(uintptr_t)sgx_e2_extract_asset, 0, 0},
		{(void*)(uintptr_t)sgx_e2_compare_hash, 0, 0},
		{(void*)(uintptr_t)sgx_e2_change_password, 0, 0},
		{(void*)(uintptr_t)sgx_e2_init_session, 0, 0},
		{(void*)(uintptr_t)sgx_e2_create_message1, 0, 0},
		{(void*)(uintptr_t)sgx_e2_process_message2, 0, 0},
		{(void*)(uintptr_t)sgx_e2_show_secret_key, 0, 0},
		{(void*)(uintptr_t)sgx_e2_seal_ciphertext, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][14];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_e2_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_e2_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_e2_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_e2_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_e2_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_e2_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

