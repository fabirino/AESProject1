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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "App.h"
#include "Enclave1_u.h"
#include "sgx_urts.h"

#define HEADER_SIZE 25
#define FILE_NAME_SIZE 20
#define AUTHOR_SIZE 10
#define PW_SIZE 10
#define NUM_ASSETS 1
#define NONCE_SIZE 4

/*
 * Error reporting
 */

typedef struct _sgx_errlist_t {
    sgx_status_t error_number;
    const char *message;
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] =
    {/* error list extracted from /opt/intel/sgxsdk/include/sgx_error.h */
     {SGX_SUCCESS, "All is well!"},
     {SGX_ERROR_UNEXPECTED, "Unexpected error"},
     {SGX_ERROR_INVALID_PARAMETER, "The parameter is incorrect"},
     {SGX_ERROR_OUT_OF_MEMORY, "Not enough memory is available to complete this operation"},
     {SGX_ERROR_ENCLAVE_LOST, "Enclave lost after power transition or used in child process created by linux:fork()"},
     {SGX_ERROR_INVALID_STATE, "SGX API is invoked in incorrect order or state"},
     {SGX_ERROR_FEATURE_NOT_SUPPORTED, "Feature is not supported on this platform"},
     {SGX_PTHREAD_EXIT, "Enclave is exited with pthread_exit()"},
     {SGX_ERROR_MEMORY_MAP_FAILURE, "Failed to reserve memory for the enclave"},
     {SGX_ERROR_INVALID_FUNCTION, "The ecall/ocall index is invalid"},
     {SGX_ERROR_OUT_OF_TCS, "The enclave is out of TCS"},
     {SGX_ERROR_ENCLAVE_CRASHED, "The enclave is crashed"},
     {SGX_ERROR_ECALL_NOT_ALLOWED, "The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization"},
     {SGX_ERROR_OCALL_NOT_ALLOWED, "The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling"},
     {SGX_ERROR_STACK_OVERRUN, "The enclave is running out of stack"},
     {SGX_ERROR_UNDEFINED_SYMBOL, "The enclave image has undefined symbol"},
     {SGX_ERROR_INVALID_ENCLAVE, "The enclave image is not correct"},
     {SGX_ERROR_INVALID_ENCLAVE_ID, "The enclave id is invalid"},
     {SGX_ERROR_INVALID_SIGNATURE, "The signature is invalid"},
     {SGX_ERROR_NDEBUG_ENCLAVE, "The enclave is signed as product enclave, and can not be created as debuggable enclave"},
     {SGX_ERROR_OUT_OF_EPC, "Not enough EPC is available to load the enclave"},
     {SGX_ERROR_NO_DEVICE, "Can't open SGX device"},
     {SGX_ERROR_MEMORY_MAP_CONFLICT, "Page mapping failed in driver"},
     {SGX_ERROR_INVALID_METADATA, "The metadata is incorrect"},
     {SGX_ERROR_DEVICE_BUSY, "Device is busy, mostly EINIT failed"},
     {SGX_ERROR_INVALID_VERSION, "Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform"},
     {SGX_ERROR_MODE_INCOMPATIBLE, "The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS"},
     {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file"},
     {SGX_ERROR_INVALID_MISC, "The MiscSelct/MiscMask settings are not correct"},
     {SGX_ERROR_INVALID_LAUNCH_TOKEN, "The launch token is not correct"},
     {SGX_ERROR_MAC_MISMATCH, "Indicates verification error for reports, sealed datas, etc"},
     {SGX_ERROR_INVALID_ATTRIBUTE, "The enclave is not authorized, e.g., requesting invalid attribute or launch key access on legacy SGX platform without FLC"},
     {SGX_ERROR_INVALID_CPUSVN, "The cpu svn is beyond platform's cpu svn value"},
     {SGX_ERROR_INVALID_ISVSVN, "The isv svn is greater than the enclave's isv svn"},
     {SGX_ERROR_INVALID_KEYNAME, "The key name is an unsupported value"},
     {SGX_ERROR_SERVICE_UNAVAILABLE, "Indicates aesm didn't respond or the requested service is not supported"},
     {SGX_ERROR_SERVICE_TIMEOUT, "The request to aesm timed out"},
     {SGX_ERROR_AE_INVALID_EPIDBLOB, "Indicates epid blob verification error"},
     {SGX_ERROR_SERVICE_INVALID_PRIVILEGE, " Enclave not authorized to run, .e.g. provisioning enclave hosted in an app without access rights to /dev/sgx_provision"},
     {SGX_ERROR_EPID_MEMBER_REVOKED, "The EPID group membership is revoked"},
     {SGX_ERROR_UPDATE_NEEDED, "SGX needs to be updated"},
     {SGX_ERROR_NETWORK_FAILURE, "Network connecting or proxy setting issue is encountered"},
     {SGX_ERROR_AE_SESSION_INVALID, "Session is invalid or ended by server"},
     {SGX_ERROR_BUSY, "The requested service is temporarily not available"},
     {SGX_ERROR_MC_NOT_FOUND, "The Monotonic Counter doesn't exist or has been invalided"},
     {SGX_ERROR_MC_NO_ACCESS_RIGHT, "Caller doesn't have the access right to specified VMC"},
     {SGX_ERROR_MC_USED_UP, "Monotonic counters are used out"},
     {SGX_ERROR_MC_OVER_QUOTA, "Monotonic counters exceeds quota limitation"},
     {SGX_ERROR_KDF_MISMATCH, "Key derivation function doesn't match during key exchange"},
     {SGX_ERROR_UNRECOGNIZED_PLATFORM, "EPID Provisioning failed due to platform not recognized by backend server"},
     {SGX_ERROR_UNSUPPORTED_CONFIG, "The config for trigging EPID Provisiong or PSE Provisiong&LTP is invalid"},
     {SGX_ERROR_NO_PRIVILEGE, "Not enough privilege to perform the operation"},
     {SGX_ERROR_PCL_ENCRYPTED, "trying to encrypt an already encrypted enclave"},
     {SGX_ERROR_PCL_NOT_ENCRYPTED, "trying to load a plain enclave using sgx_create_encrypted_enclave"},
     {SGX_ERROR_PCL_MAC_MISMATCH, "section mac result does not match build time mac"},
     {SGX_ERROR_PCL_SHA_MISMATCH, "Unsealed key MAC does not match MAC of key hardcoded in enclave binary"},
     {SGX_ERROR_PCL_GUID_MISMATCH, "GUID in sealed blob does not match GUID hardcoded in enclave binary"},
     {SGX_ERROR_FILE_BAD_STATUS, "The file is in bad status, run sgx_clearerr to try and fix it"},
     {SGX_ERROR_FILE_NO_KEY_ID, "The Key ID field is all zeros, can't re-generate the encryption key"},
     {SGX_ERROR_FILE_NAME_MISMATCH, "The current file name is different then the original file name (not allowed, substitution attack)"},
     {SGX_ERROR_FILE_NOT_SGX_FILE, "The file is not an SGX file"},
     {SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE, "A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)"},
     {SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE, "A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)"},
     {SGX_ERROR_FILE_RECOVERY_NEEDED, "When openeing the file, recovery is needed, but the recovery process failed"},
     {SGX_ERROR_FILE_FLUSH_FAILED, "fflush operation (to disk) failed (only used when no EXXX is returned)"},
     {SGX_ERROR_FILE_CLOSE_FAILED, "fclose operation (to disk) failed (only used when no EXXX is returned)"},
     {SGX_ERROR_UNSUPPORTED_ATT_KEY_ID, "platform quoting infrastructure does not support the key"},
     {SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE, "Failed to generate and certify the attestation key"},
     {SGX_ERROR_ATT_KEY_UNINITIALIZED, "The platform quoting infrastructure does not have the attestation key available to generate quote"},
     {SGX_ERROR_INVALID_ATT_KEY_CERT_DATA, "TThe data returned by the platform library's sgx_get_quote_config() is invalid"},
     {SGX_ERROR_PLATFORM_CERT_UNAVAILABLE, "The PCK Cert for the platform is not available"},
     {SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, "The ioctl for enclave_create unexpectedly failed with EINTR"}};

void print_error_message(sgx_status_t ret, const char *sgx_function_name) {
    size_t ttl = sizeof(sgx_errlist) / sizeof(sgx_errlist[0]);
    size_t idx;

    if (sgx_function_name != NULL)
        printf("Function: %s\n", sgx_function_name);
    for (idx = 0; idx < ttl; idx++) {
        if (ret == sgx_errlist[idx].error_number) {
            printf("Error: %s\n", sgx_errlist[idx].message);
            break;
        }
    }
    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/*
 * Aux Functions
 */

/*
 * Enclave1 stuff
 */

sgx_enclave_id_t global_eid1 = 0;

int initialize_enclave1(void) {
    sgx_status_t ret;

    if ((ret = sgx_create_enclave(ENCLAVE1_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid1, NULL)) != SGX_SUCCESS) {
        print_error_message(ret, "sgx_create_enclave");
        return -1;
    }
    return 0;
}

void ocall_e1_print_string(const char *str) {
    printf("%s", str);
}

int TPDV_exists(unsigned char *file_name) {
    char path[FILE_NAME_SIZE + 8] = "./TPDVs/";

    for (int i = 0; i < FILE_NAME_SIZE; i++) {
        if (file_name[i] == '\0') {
            break;
        }
        path[8 + i] = file_name[i];
    }

    FILE *file = fopen((char *)path, "r");
    if (file) {
        fclose(file);
        return 1;
    }

    return 0;
}

int asset_exists(unsigned char *asset_name) {
    char path[FILE_NAME_SIZE + 9] = "./Assets/";

    for (int i = 0; i < FILE_NAME_SIZE; i++) {
        if (asset_name[i] == '\0') {
            break;
        }
        path[9 + i] = asset_name[i];
    }

    FILE *file = fopen((char *)path, "rb");
    if (file) {
        fclose(file);
        return 1;
    }

    return 0;
}

uint32_t get_TPDV_size(unsigned char *file_name) {
    char path[FILE_NAME_SIZE + 8] = "./TPDVs/";

    for (int i = 0; i < FILE_NAME_SIZE; i++) {
        if (file_name[i] == '\0') {
            break;
        }
        path[8 + i] = file_name[i];
    }

    FILE *file = fopen((char *)path, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        uint32_t size = ftell(file);
        fclose(file);
        return size;
    }

    return 0;
}

uint32_t get_asset_size(unsigned char *asset_name) {
    char path[FILE_NAME_SIZE + 9] = "./Assets/";

    for (int i = 0; i < FILE_NAME_SIZE; i++) {
        if (asset_name[i] == '\0') {
            break;
        }
        path[9 + i] = asset_name[i];
    }

    FILE *file = fopen((char *)path, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        uint32_t size = ftell(file);
        fclose(file);
        return size;
    }

    return 0;
}

void save_sealed_data(unsigned char *file_name, unsigned char *sealed_data, size_t sealed_data_size) {
    char path[FILE_NAME_SIZE + 8] = "./TPDVs/";

    for (int i = 0; i < FILE_NAME_SIZE; i++) {
        if (file_name[i] == '\0') {
            break;
        }
        path[8 + i] = file_name[i];
    }

    FILE *file = fopen((char *)path, "wb");
    if (file) {
        fwrite(sealed_data, 1, sealed_data_size, file);
        fclose(file);
    }
}

void load_sealed_data(unsigned char *file_name, unsigned char *sealed_data, size_t sealed_data_size) {
    char path[FILE_NAME_SIZE + 8] = "./TPDVs/";

    for (int i = 0; i < FILE_NAME_SIZE; i++) {
        if (file_name[i] == '\0') {
            break;
        }
        path[8 + i] = file_name[i];
    }

    FILE *file = fopen((char *)path, "rb");
    if (file) {
        fread(sealed_data, 1, sealed_data_size, file);
        fclose(file);
    }
}

void load_asset(unsigned char *asset_name, unsigned char *asset, size_t asset_size) {
    char path[FILE_NAME_SIZE + 9] = "./Assets/";

    for (int i = 0; i < FILE_NAME_SIZE; i++) {
        if (asset_name[i] == '\0') {
            break;
        }
        path[9 + i] = asset_name[i];
    }

    FILE *file = fopen((char *)path, "rb");
    if (file) {
        fread(asset, 1, asset_size, file);
        fclose(file);
    }
}

void save_asset(unsigned char *asset_name, unsigned char *asset_content, size_t asset_size) {
    char path[FILE_NAME_SIZE + 14] = "./Extractions/";

    for (int i = 0; i < FILE_NAME_SIZE; i++) {
        if (asset_name[i] == '\0') {
            break;
        }
        path[14 + i] = asset_name[i];
    }

    FILE *file = fopen((char *)path, "wb");
    if (file) {
        fwrite(asset_content, 1, asset_size, file);
        fclose(file);
    }
}

/*
 * Application entry
 */

// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
// =========================================================================================================================================
// #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

int SGX_CDECL main(int argc, char *argv[]) {
    sgx_status_t ret;

    if (initialize_enclave1() < 0)
        return 1;

    int terminar = 0;
    int opcao = -1;
    unsigned char file_name[FILE_NAME_SIZE] = {};
    unsigned char author[AUTHOR_SIZE] = {};
    unsigned char password[PW_SIZE] = {};
    unsigned char assets = '\0';
    unsigned char asset_name[FILE_NAME_SIZE] = {};
    unsigned char *asset;
    uint32_t asset_size = 0;
    int indice = 0;
    unsigned char hash[32] = {};
    size_t hash_size = 0;
    uint32_t sealed_data_size = 0;
    uint32_t unsealed_data_size = 0;
    uint32_t tpdv_data_size = 0;
    unsigned char *sealed_data = NULL;
    unsigned char *unsealed_data = NULL;
    unsigned char *tpdv_data = NULL;
    uint32_t total_size = 0;
    unsigned char new_password[PW_SIZE] = {0};

    int i = 0;
    int byte;

    printf(" _____                                       ___                  __      ___ _       _ _        _                    _ _   \n");
    printf("/__   \\__ _ _ __ ___  _ __   ___ _ __       / _ \\_ __ ___   ___  / _|    /   (_) __ _(_) |_ __ _| | /\\   /\\__ _ _   _| | |_ \n");
    printf("  / /\\/ _` | '_ ` _ \\| '_ \\ / _ \\ '__|____ / /_)/ '__/ _ \\ / _ \\| |_    / /\\ / |/ _` | | __/ _` | | \\ \\ / / _` | | | | | __|\n");
    printf(" / / | (_| | | | | | | |_) |  __/ | |_____/ ___/| | | (_) | (_) |  _|  / /_//| | (_| | | || (_| | |  \\ V / (_| | |_| | | |_ \n");
    printf(" \\/   \\__,_|_| |_| |_| .__/ \\___|_|       \\/    |_|  \\___/ \\___/|_|   /___,' |_|\\__, |_|\\__\\__,_|_|   \\_/ \\__,_|\\__,_|_|\\__|\n");
    printf("                     |_|                                                        |___/                                       \n");

    while (!terminar) {

        // Reset variables after each iteration of the loop
        memset(file_name, 0, FILE_NAME_SIZE);
        memset(author, 0, AUTHOR_SIZE);
        memset(password, 0, PW_SIZE);
        assets = '\0';
        memset(asset_name, 0, FILE_NAME_SIZE);
        asset = NULL;
        asset_size = 0;
        indice = 0;
        memset(hash, 0, 32);
        hash_size = 0;
        sealed_data_size = 0;
        unsealed_data_size = 0;
        sealed_data = NULL;
        unsealed_data = NULL;
        tpdv_data = NULL;
        tpdv_data_size = 0;
        total_size = 0;
        memset(new_password, 0, PW_SIZE);

        // Print menu
        printf("\nSelecione uma opção\n");
        printf("1 - Criar um novo TPDV file\n");
        printf("2 - Adicionar um asset (ficheiro binário) ao TPDV\n");
        printf("3 - Listar todos os assets guardados num TPDV file\n");
        printf("4 - Extrair um asset\n");
        printf("5 - Comparar um hash com o hash de um asset presente num TPDV\n");
        printf("6 - Mudar a password de um TPDV\n");
        printf("7 - Clonar o conteudo do TPDV\n");
        printf("0 - Sair\n");
        printf("> ");

        opcao = getchar();
        getchar();
        printf("\n");

        switch (opcao) {
        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        // =================================================================== 1 ===================================================================
        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        case '1':
            // Criar um novo TPDV file

            printf("Introduza o nome do ficheiro TPDV: ");
            fgets((char *)file_name, FILE_NAME_SIZE, stdin);
            for (int j = 0; j < FILE_NAME_SIZE; j++) {
                if (file_name[j] == '\n') {
                    file_name[j] = '\0';
                    break;
                }
            }

            printf("Introduza o nome do autor: ");
            fgets((char *)author, AUTHOR_SIZE, stdin);
            for (int j = 0; j < AUTHOR_SIZE; j++) {
                if (author[j] == '\n') {
                    author[j] = '\0';
                    break;
                }
            }

            printf("Introduza uma palavra passe: ");
            fgets((char *)password, PW_SIZE, stdin);
            for (int j = 0; j < PW_SIZE; j++) {
                if (password[j] == '\n') {
                    password[j] = '\0';
                    break;
                }
            }
            printf("\n");

            // Verificar se o ficheiro existe
            if (TPDV_exists(file_name)) {
                printf("Operação cancelada: o ficheiro já existe.\n");
                break;
            }

            if ((ret = e1_get_sealed_data_size(global_eid1, &sealed_data_size, HEADER_SIZE)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_get_sealed_data_size");
                return 1;
            }

            sealed_data = (unsigned char *)malloc(sealed_data_size);

            // ecall para criar o TPDV
            if ((ret = e1_create_tpdv(global_eid1, author, password, AUTHOR_SIZE, PW_SIZE, sealed_data, sealed_data_size)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_create_tpdv");
                return 1;
            }

            // Guardar o ficheiro
            save_sealed_data(file_name, sealed_data, sealed_data_size);
            free(sealed_data);

            break;

        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        // =================================================================== 2 ===================================================================
        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        case '2':
            // 2 - Adicionar um asset (ficheiro binário) ao TPDV

            printf("Introduza o nome do ficheiro TPDV: ");
            fgets((char *)file_name, FILE_NAME_SIZE, stdin);
            for (int j = 0; j < FILE_NAME_SIZE; j++) {
                if (file_name[j] == '\n') {
                    file_name[j] = '\0';
                    break;
                }
            }

            printf("Introduza o nome do autor: ");
            fgets((char *)author, AUTHOR_SIZE, stdin);
            for (int j = 0; j < AUTHOR_SIZE; j++) {
                if (author[j] == '\n') {
                    author[j] = '\0';
                    break;
                }
            }

            printf("Introduza uma palavra passe: ");
            fgets((char *)password, PW_SIZE, stdin);
            for (int j = 0; j < PW_SIZE; j++) {
                if (password[j] == '\n') {
                    password[j] = '\0';
                    break;
                }
            }

            printf("Introduza o nome do asset: ");
            fgets((char *)asset_name, FILE_NAME_SIZE, stdin);
            for (int j = 0; j < FILE_NAME_SIZE; j++) {
                if (asset_name[j] == '\n') {
                    asset_name[j] = '\0';
                    break;
                }
            }
            printf("\n");

            // Verificar se o ficheiro existe
            if (!TPDV_exists(file_name)) {
                printf("Operação cancelada: o ficheiro não existe.\n");
                break;
            }

            // Verificar se o asset existe
            if (!asset_exists(asset_name)) {
                printf("Operação cancelada: o asset não existe..\n");
                break;
            }

            // Carregar o TPDV
            tpdv_data_size = get_TPDV_size(file_name);
            tpdv_data = (unsigned char *)malloc(tpdv_data_size);
            load_sealed_data(file_name, tpdv_data, tpdv_data_size);

            // Carregar o asset
            asset_size = get_asset_size(asset_name);
            asset = (unsigned char *)malloc(asset_size);
            load_asset(asset_name, asset, asset_size);

            // Alocar memoria para a sealed data = tamanho do TPDV (unsealed) + tamanho do asset
            if ((ret = e1_get_unsealed_data_size(global_eid1, &unsealed_data_size, tpdv_data, tpdv_data_size)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_get_unsealed_data_size");
                return 1;
            }

            // total_zise é a variavel responsavel por guardar o tamanho do TPDV (unsealed) mais o asset sem estarem sealed
            total_size = unsealed_data_size + asset_size + FILE_NAME_SIZE + 4; // 20 para o nome do asset e 4 para o tamanho do asset

            if ((ret = e1_get_sealed_data_size(global_eid1, &sealed_data_size, total_size)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_get_sealed_data_size");
                return 1;
            }

            sealed_data = (unsigned char *)malloc(sealed_data_size);

            // ecall para adicionar o asset
            if ((ret = e1_add_asset(global_eid1, tpdv_data, author, password, asset_name, asset, unsealed_data_size, tpdv_data_size, AUTHOR_SIZE, PW_SIZE, FILE_NAME_SIZE, asset_size, sealed_data, sealed_data_size)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_add_asset");
                return 1;
            }

            // Guardar no ficheiro
            save_sealed_data(file_name, sealed_data, sealed_data_size);

            free(tpdv_data);
            free(sealed_data);
            free(asset);

            break;

        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        // =================================================================== 3 ===================================================================
        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        case '3':
            // 3 - Listar todos os assets guardados num TPDV file

            printf("Introduza o nome do ficheiro TPDV: ");
            fgets((char *)file_name, FILE_NAME_SIZE, stdin);
            for (int j = 0; j < FILE_NAME_SIZE; j++) {
                if (file_name[j] == '\n') {
                    file_name[j] = '\0';
                    break;
                }
            }

            printf("Introduza o seu nome: ");
            fgets((char *)author, AUTHOR_SIZE, stdin);
            for (int j = 0; j < AUTHOR_SIZE; j++) {
                if (author[j] == '\n') {
                    author[j] = '\0';
                    break;
                }
            }

            printf("Introduza a sua palavra passe: ");
            fgets((char *)password, PW_SIZE, stdin);
            for (int j = 0; j < PW_SIZE; j++) {
                if (password[j] == '\n') {
                    password[j] = '\0';
                    break;
                }
            }
            printf("\n");

            // Verificar se o ficheiro existe
            if (!TPDV_exists(file_name)) {
                printf("Operação cancelada: o ficheiro não existe.\n");
                break;
            }

            sealed_data_size = get_TPDV_size(file_name);
            sealed_data = (unsigned char *)malloc(sealed_data_size);

            load_sealed_data(file_name, sealed_data, sealed_data_size);

            if ((ret = e1_get_unsealed_data_size(global_eid1, &unsealed_data_size, sealed_data, sealed_data_size)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_get_unsealed_data_size");
                return 1;
            }

            // ecall para listar os assets
            if ((ret = e1_list_assets(global_eid1, file_name, sealed_data, author, password, FILE_NAME_SIZE, sealed_data_size, AUTHOR_SIZE, PW_SIZE)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_list_assets");
                return 1;
            }

            break;

        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        // =================================================================== 4 ===================================================================
        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        case '4':

            // 4 - Extrair um asset

            printf("Introduza o nome do ficheiro TPDV: ");
            fgets((char *)file_name, FILE_NAME_SIZE, stdin);
            for (int j = 0; j < FILE_NAME_SIZE; j++) {
                if (file_name[j] == '\n') {
                    file_name[j] = '\0';
                    break;
                }
            }

            printf("Introduza o seu nome: ");
            fgets((char *)author, AUTHOR_SIZE, stdin);
            for (int j = 0; j < AUTHOR_SIZE; j++) {
                if (author[j] == '\n') {
                    author[j] = '\0';
                    break;
                }
            }

            printf("Introduza a sua palavra passe: ");
            fgets((char *)password, PW_SIZE, stdin);
            for (int j = 0; j < PW_SIZE; j++) {
                if (password[j] == '\n') {
                    password[j] = '\0';
                    break;
                }
            }

            printf("Introduza o índice do asset: ");
            scanf("%d", &indice);
            getchar();
            printf("\n");

            // Verificar se o ficheiro existe
            if (!TPDV_exists(file_name)) {
                printf("Operação cancelada: o ficheiro não existe.\n");
                break;
            }

            // Carregar o TPDV
            tpdv_data_size = get_TPDV_size(file_name);
            tpdv_data = (unsigned char *)malloc(tpdv_data_size);
            load_sealed_data(file_name, tpdv_data, tpdv_data_size);

            // Obter o tamanho do asset (unsealed)
            if ((ret = e1_get_asset_size(global_eid1, &asset_size, tpdv_data, indice, tpdv_data_size)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_get_asset_size");
                return 1;
            }

            unsealed_data = (unsigned char *)malloc(asset_size);

            // ecall para extrair o asset
            if ((ret = e1_extract_asset(global_eid1, tpdv_data, author, password, indice, tpdv_data_size, AUTHOR_SIZE, PW_SIZE, unsealed_data, asset_name, asset_size, FILE_NAME_SIZE)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_extract_asset");
                return 1;
            }

            // // DEBUG:
            // printf("Asset name: %s\n", asset_name);
            // printf("Content: %s\n", unsealed_data);

            // Guardar o asset
            save_asset(asset_name, unsealed_data, asset_size);

            free(tpdv_data);
            free(unsealed_data);

            break;

        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        // =================================================================== 5 ===================================================================
        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        case '5':
            // 5 - Comparar um hash com o hash de um asset presente num TPDV

            printf("Introduza o nome do ficheiro TPDV: ");
            fgets((char *)file_name, FILE_NAME_SIZE, stdin);
            for (int j = 0; j < FILE_NAME_SIZE; j++) {
                if (file_name[j] == '\n') {
                    file_name[j] = '\0';
                    break;
                }
            }

            printf("Introduza o seu nome: ");
            fgets((char *)author, AUTHOR_SIZE, stdin);
            for (int j = 0; j < AUTHOR_SIZE; j++) {
                if (author[j] == '\n') {
                    author[j] = '\0';
                    break;
                }
            }

            printf("Introduza a sua palavra passe: ");
            fgets((char *)password, PW_SIZE, stdin);
            for (int j = 0; j < PW_SIZE; j++) {
                if (password[j] == '\n') {
                    password[j] = '\0';
                    break;
                }
            }

            printf("Introduza o índice do asset: ");
            scanf("%d", &indice);
            getchar();

            // ecall para comparar o hash
            if ((ret = e1_compare_hash(global_eid1, author, password, indice, AUTHOR_SIZE, PW_SIZE, hash, hash_size)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_compare_hash");
                return 1;
            }

            break;

        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        // =================================================================== 6 ===================================================================
        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        case '6':
            // 6 - Mudar a password de um TPDV

            printf("Introduza o nome do ficheiro TPDV: ");
            fgets((char *)file_name, FILE_NAME_SIZE, stdin);
            for (int j = 0; j < FILE_NAME_SIZE; j++) {
                if (file_name[j] == '\n') {
                    file_name[j] = '\0';
                    break;
                }
            }

            printf("Introduza o seu nome: ");
            fgets((char *)author, AUTHOR_SIZE, stdin);
            for (int j = 0; j < AUTHOR_SIZE; j++) {
                if (author[j] == '\n') {
                    author[j] = '\0';
                    break;
                }
            }

            printf("Introduza a sua palavra passe atual: ");
            fgets((char *)password, PW_SIZE, stdin);
            for (int j = 0; j < PW_SIZE; j++) {
                if (password[j] == '\n') {
                    password[j] = '\0';
                    break;
                }
            }

            printf("Introduza a nova palavra passe: ");
            fgets((char *)new_password, PW_SIZE, stdin);
            for (int j = 0; j < PW_SIZE; j++) {
                if (new_password[j] == '\n') {
                    new_password[j] = '\0';
                    break;
                }
            }

            if (!TPDV_exists(file_name)) {
                printf("Operação cancelada: o ficheiro não existe.\n");
                break;
            }

            // Carregar o TPDV
            tpdv_data_size = get_TPDV_size(file_name);
            tpdv_data = (unsigned char *)malloc(tpdv_data_size);
            load_sealed_data(file_name, tpdv_data, tpdv_data_size);

            sealed_data = (unsigned char *)malloc(tpdv_data_size); // same size as tpdv_data

            // ecall para mudar a password
            if ((ret = e1_change_password(global_eid1, tpdv_data, author, password, new_password, tpdv_data_size, AUTHOR_SIZE, PW_SIZE, PW_SIZE, sealed_data, tpdv_data_size)) != SGX_SUCCESS) {
                print_error_message(ret, "e1_change_password");
                return 1;
            }

            // Guardar o ficheiro
            // save_sealed_data(file_name, sealed_data, tpdv_data_size);

            


            break;

        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        // =================================================================== 7 ===================================================================
        // #=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        case '7':
            // 7 - Clonar o conteudo do TPDV

            break;
        case '0':
            terminar = 1;
            break;
        default:
            printf("Opção Inválida\n");
            break;
        }
    }

    if ((ret = sgx_destroy_enclave(global_eid1)) != SGX_SUCCESS) {
        print_error_message(ret, "sgx_destroy_enclave");
        return 1;
    }
    return 0;
}
