/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _ENCLAVE1_H_
#define _ENCLAVE1_H_
#include <stdlib.h>
#include <wchar.h>
#include <assert.h>

#include "sgx_tcrypto.h"
#include "sgx_tprotected_fs.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"


#if defined(__cplusplus)
extern "C" {
#endif

#include "sgx_dh.h"

int printf(const char *fmt, ...);
uint32_t e1_get_sealed_data_size(uint32_t data_size);
uint32_t e1_get_unsealed_data_size(unsigned char *sealed_data, uint32_t sealed_data_size);

int e1_check_credentials(unsigned char *tpdv_data, unsigned char *author, unsigned char *password, uint32_t tpdv_data_size, size_t author_leh, size_t password_len);
void e1_create_tpdv(unsigned char *author, unsigned char *password, size_t author_len, size_t password_len, unsigned char *sealed_data, uint32_t sealed_data_size);
void e1_add_asset(unsigned char *tpdv_data, unsigned char *author, unsigned char *password, unsigned char *asset_name, unsigned char *asset_content, uint32_t tpdv_data_size_unsealed, uint32_t tpdv_data_size_sealed, size_t author_len, size_t password_len, size_t asset_name_len, uint32_t asset_content_len, unsigned char *sealed_data, uint32_t sealed_data_size);
void e1_list_assets(unsigned char * file_name, unsigned char *sealed_data, unsigned char *author, unsigned char *password, size_t file_name_size, uint32_t sealed_data_size, size_t author_len, size_t password_len);
uint32_t e1_get_asset_size(unsigned char *sealed_data, int indice, uint32_t sealed_data_size);
void e1_extract_asset(unsigned char *sealed_data, unsigned char *author, unsigned char *password, int indice, uint32_t sealed_data_size, size_t author_len, size_t password_len, unsigned char *unsealed_data, unsigned char* asset_name, uint32_t asset_size, size_t asset_name_len);
void e1_compare_hash(unsigned char *tpdv_data, unsigned char *author, unsigned char *password, int indice, unsigned char *hash, uint32_t tpdv_data_size, size_t author_len, size_t password_len, size_t hash_len);
void e1_change_password(unsigned char *tpdv_data, unsigned char *author, unsigned char *password, unsigned char *new_password, uint32_t tpdv_data_size, size_t author_len, size_t password_len, size_t new_password_len, unsigned char *sealed_data, uint32_t sealed_data_size);

void e1_init_session(sgx_status_t *dh_status);
void e1_process_message1(const sgx_dh_msg1_t *msg1, sgx_dh_msg2_t *msg2, sgx_status_t *dh_status);
void e1_process_message3(const sgx_dh_msg3_t *msg3, sgx_status_t *dh_status);
void e1_show_secret_key(void);

void e1_get_TPDV_ciphered(unsigned char *tpdv_data, uint32_t tpdv_data_size, unsigned char *ciphered_tpdv_data, uint32_t ciphered_tpdv_data_size);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE1_H_ */
