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

#include <cstdint>
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <stdlib.h>
#include <string.h>

#include "Enclave1.h"
#include "Enclave1_t.h" /* e1_print_string */
#include "sgx_tprotected_fs.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#define HEADER_SIZE 25
#define AUTHOR_SIZE 10
#define PW_SIZE 10
#define NUM_ASSETS 1
#define NONCE_SIZE 4

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;

    va_start(ap, fmt);
    (void)vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_e1_print_string(buf);
    return 0;
}

/*
 * ECALL (it just prints a string)
 */

// FIXME:
char aad_mac_text[BUFSIZ] = "aad mac text";

uint32_t e1_get_sealed_data_size(uint32_t data_size) {
    return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), data_size);
}

void seal_data(unsigned char *data, uint32_t data_size, unsigned char *sealed_data) {
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), data_size);
    if (sealed_data_size == UINT32_MAX) {
        printf("ENCLAVE: Error calculating sealed data size\n");
        return;
    }

    unsigned char *temp_seal_buf = (unsigned char *)malloc(sealed_data_size);
    if (temp_seal_buf == NULL) {
        printf("ENCLAVE: Error allocating memory for sealed data\n");
        return;
    }

    if (sgx_seal_data((uint32_t)strlen(aad_mac_text), (const uint8_t *)aad_mac_text, data_size, (const uint8_t *)data, sealed_data_size, (sgx_sealed_data_t *)temp_seal_buf) != SGX_SUCCESS) {
        printf("ENCLAVE: Error sealing data\n");
        return;
    }

    memcpy(sealed_data, temp_seal_buf, sealed_data_size);

    free(temp_seal_buf);
}

uint32_t e1_get_unsealed_data_size(unsigned char *sealed_data, uint32_t sealed_data_size) {
    return sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);
}

void unseal_data(const uint8_t *sealed_data, size_t sealed_data_size, unsigned char *unsealed_data) {
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_data);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return;
    if (mac_text_len > sealed_data_size || decrypt_data_len > sealed_data_size)
        return;

    uint8_t *de_mac_text = (uint8_t *)malloc(mac_text_len);
    if (de_mac_text == NULL)
        return;

    if (unsealed_data == NULL) {
        free(de_mac_text);
        return;
    }

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_data, de_mac_text, &mac_text_len, unsealed_data, &decrypt_data_len);
    if (ret != SGX_SUCCESS) {
        free(de_mac_text);
        return;
    }

    if (memcmp(de_mac_text, aad_mac_text, strlen(aad_mac_text))) {
        ret = SGX_ERROR_UNEXPECTED;
    }

    // TODO: Comparar nonce aqui

    free(de_mac_text);
}

int check_credentials(unsigned char *actual_password, unsigned char *actual_author, unsigned char *password, unsigned char *author) {
    if (strcmp((char *)actual_password, (char *)password) == 0 && strcmp((char *)actual_author, (char *)author) == 0) {
        return 1;
    } else {
        return 0;
    }
}

// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
// =================================================================== 1 ===================================================================
// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

void e1_create_tpdv(unsigned char *author, unsigned char *password, size_t author_len, size_t password_len, unsigned char *sealed_data, uint32_t sealed_data_len) {
    printf("ENCLAVE: Creating TPDV for author: %s \n", author);

    unsigned char header[HEADER_SIZE] = {0};

    // Create the header
    for (int i = 0; i < strlen((char *)author); i++) {
        if (author[i] != '\0')
            header[i] = author[i];
    }

    for (int i = 0; i < strlen((char *)password); i++) {
        if (password[i] != '\0')
            header[i + AUTHOR_SIZE] = password[i];
    }

    header[AUTHOR_SIZE + PW_SIZE] = 0; // Number of assets

    for (int i = 0; i < NONCE_SIZE; i++) {
        header[AUTHOR_SIZE + PW_SIZE + 1 + i] = 0;
    }

    // Seal the header
    unsigned char *temp_buf = (unsigned char *)malloc(sealed_data_len);
    if (temp_buf == NULL) {
        printf("ENCLAVE: Error allocating memory for sealed data\n");
        return;
    }

    seal_data(header, HEADER_SIZE, temp_buf);
    memcpy(sealed_data, temp_buf, sealed_data_len);

    free(temp_buf);
}

// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
// =================================================================== 2 ===================================================================
// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

void e1_add_asset(unsigned char *tpdv_data, unsigned char *author, unsigned char *password, unsigned char *asset_name, unsigned char *asset_content, uint32_t tpdv_data_size_unsealed, uint32_t tpdv_data_size_sealed, size_t author_len, size_t password_len, size_t asset_name_len, uint32_t asset_content_len, unsigned char *sealed_data, uint32_t sealed_data_size) {
    printf("ENCLAVE: Adding asset: %s\n", asset_name);

    // // Unseal the data
    // unsigned char *temp_buf = (unsigned char *)malloc(tpdv_data_size_unsealed);
    // if (temp_buf == NULL) {
    //     printf("ENCLAVE: Error allocating memory for sealed data\n");
    //     return;
    // }

    // unseal_data(tpdv_data, tpdv_data_size_sealed, temp_buf);


    // // Check credentials
    // unsigned char actual_author[AUTHOR_SIZE] = {0};
    // unsigned char actual_password[PW_SIZE] = {0};
    // memcpy(actual_author, temp_buf, AUTHOR_SIZE);
    // memcpy(actual_password, temp_buf + AUTHOR_SIZE, PW_SIZE);

    // if (!check_credentials(actual_password, actual_author, password, author)) {
    //     printf("ENCLAVE: Invalid credentials\n");
    //     return;
    // }

    // // Add the asset to the TPDV
    // unsigned char *new_tpdv_data = (unsigned char *)malloc(tpdv_data_size_sealed + asset_content_len + asset_name_len + 4); // 4 = bytes to store the size of the asset

    // if (new_tpdv_data == NULL) {
    //     printf("ENCLAVE: Error allocating memory for new TPDV data\n");
    //     return;
    // }

    // // Convert the asset size to a byte array
    // unsigned char asset_size_bytes[4];
    // asset_size_bytes[0] = (asset_content_len >> 24) & 0xFF;
    // asset_size_bytes[1] = (asset_content_len >> 16) & 0xFF;
    // asset_size_bytes[2] = (asset_content_len >> 8) & 0xFF;
    // asset_size_bytes[3] = asset_content_len & 0xFF;

    // // Add the asset to the TPDV
    // memcpy(new_tpdv_data, temp_buf, tpdv_data_size_unsealed);
    // memcpy(new_tpdv_data + tpdv_data_size_sealed, asset_name, asset_name_len);
    // memcpy(new_tpdv_data + tpdv_data_size_sealed + asset_name_len, asset_size_bytes, 4);
    // memcpy(new_tpdv_data + tpdv_data_size_sealed + asset_name_len + 4, asset_content, asset_content_len);

    // // DEBUG: 
    // for (int i = 0; i < tpdv_data_size_sealed + asset_name_len + 4 + asset_content_len; i++) {
    //     if (new_tpdv_data[i] != '\0')
    //         printf("ENCLAVE: new_tpdv_data[%d]: %c\n", i, new_tpdv_data[i]);
    //     else
    //         printf("ENCLAVE: new_tpdv_data[%d]: \\0\n", i);
    // }

    // // Seal the new TPDV data
    // unsigned char *temp_buf2 = (unsigned char *)malloc(sealed_data_size);
    // if (temp_buf2 == NULL) {
    //     printf("ENCLAVE: Error allocating memory for sealed data\n");
    //     return;
    // }

    // seal_data(new_tpdv_data, tpdv_data_size_sealed + asset_name_len + 4 + asset_content_len, temp_buf2);
    // memcpy(sealed_data, temp_buf2, sealed_data_size);


    // free(temp_buf);
    // free(new_tpdv_data);
    // free(temp_buf2);


    // Unseal the data
    unsigned char *temp_buf = (unsigned char *)malloc(tpdv_data_size_unsealed);
    if (temp_buf == NULL) {
        printf("ENCLAVE: Error allocating memory for sealed data\n");
        return;
    }

    unseal_data(tpdv_data, tpdv_data_size_sealed, temp_buf);

    // Check credentials
    unsigned char actual_author[AUTHOR_SIZE] = {0};
    unsigned char actual_password[PW_SIZE] = {0};
    memcpy(actual_author, temp_buf, AUTHOR_SIZE);
    memcpy(actual_password, temp_buf + AUTHOR_SIZE, PW_SIZE);

    if (!check_credentials(actual_password, actual_author, password, author)) {
        printf("ENCLAVE: Invalid credentials\n");
        return;
    }

    // Add the asset to the TPDV
    unsigned char *new_tpdv_data = (unsigned char *)malloc(tpdv_data_size_unsealed + asset_content_len + asset_name_len + 4); // 4 = bytes to store the size of the asset

    if (new_tpdv_data == NULL) {
        printf("ENCLAVE: Error allocating memory for new TPDV data\n");
        return;
    }

    // Convert the asset size to a byte array
    unsigned char asset_size_bytes[4];
    asset_size_bytes[0] = (asset_content_len >> 24) & 0xFF;
    asset_size_bytes[1] = (asset_content_len >> 16) & 0xFF;
    asset_size_bytes[2] = (asset_content_len >> 8) & 0xFF;
    asset_size_bytes[3] = asset_content_len & 0xFF;

    // Add the asset to the TPDV
    memcpy(new_tpdv_data, temp_buf, tpdv_data_size_unsealed);
    memcpy(new_tpdv_data + tpdv_data_size_unsealed, asset_name, asset_name_len);
    memcpy(new_tpdv_data + tpdv_data_size_unsealed + asset_name_len, asset_size_bytes, 4);
    memcpy(new_tpdv_data + tpdv_data_size_unsealed + asset_name_len + 4, asset_content, asset_content_len);

    // DEBUG:
    // for (int i = 0; i < tpdv_data_size_unsealed + asset_name_len + 4 + asset_content_len; i++) {
    //     if (new_tpdv_data[i] != '\0')
    //         printf("ENCLAVE: new_tpdv_data[%d]: %c\n", i, new_tpdv_data[i]);
    //     else
    //         printf("ENCLAVE: new_tpdv_data[%d]: \\0\n", i);
    // }




}

// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
// =================================================================== 3 ===================================================================
// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

void e1_list_assets(unsigned char *sealed_data, unsigned char *author, unsigned char *password, uint32_t sealed_data_size, size_t author_len, size_t password_len) {
    printf("ENCLAVE: Listing assets from TPDV\n");

    unsigned char *temp_buf = (unsigned char *)malloc(sealed_data_size);
    if (temp_buf == NULL) {
        printf("ENCLAVE: Error allocating memory for sealed data\n");
        return;
    }

    unseal_data(sealed_data, sealed_data_size, temp_buf);

    // Check credentials
    unsigned char actual_author[AUTHOR_SIZE] = {0};
    unsigned char actual_password[PW_SIZE] = {0};
    memcpy(actual_author, temp_buf, AUTHOR_SIZE);
    memcpy(actual_password, temp_buf + AUTHOR_SIZE, PW_SIZE);

    // DEBUG:
    // printf("ENCLAVE: Actual author: %s\n", actual_author);
    // printf("ENCLAVE: Actual password: %s\n", actual_password);

    if (!check_credentials(actual_password, actual_author, password, author)) {
        printf("ENCLAVE: Invalid credentials\n");
        return;
    }


    free(temp_buf);

    // DEBUG:
    // printf("ENCLAVE: Unsealed data size: %d\n", unsealed_data_size);
    // for (int i = 0; i < unsealed_data_size; i++) {
    //     if (unsealed_data[i] != '\0')
    //         printf("ENCLAVE: unsealed_data[%d]: %c\n", i, unsealed_data[i]);
    //     else
    //         printf("ENCLAVE: unsealed_data[%d]: \\0\n", i);
    // }
}

// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
// =================================================================== 4 ===================================================================
// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

void e1_extract_asset(unsigned char *file_name, unsigned char *author, unsigned char *password, int indice, size_t file_name_len, size_t author_len, size_t password_len) {
    printf("ENCLAVE: Extracting asset %d from TPDV: %s\n", indice, file_name);
}

// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
// =================================================================== 5 ===================================================================
// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

void e1_compare_hash(unsigned char *file_name, unsigned char *author, unsigned char *password, int indice, unsigned char *hash, int hash_type, size_t file_name_len, size_t author_len, size_t password_len, size_t hash_len) {
    printf("ENCLAVE: Comparing hash of asset %d from TPDV: %s\n", indice, file_name);

    if (hash_type == 1) {
        printf("ENCLAVE: Hash type: MD5\n");
    } else {
        printf("ENCLAVE: Hash type: SHA256\n");
    }
}

// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
// =================================================================== 6 ===================================================================
// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

void e1_change_password() {
}