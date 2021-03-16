/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * get.c
 *
 *  Created on: 18-Feb-2020
 *      Author: Arvind Rawat
 */

#include <kmip/kmip_memset.h>

#include "common.h"
#include "util.h"
#include "logging.h"

extern FILE *log_fp;

/*
* get:
*
* @id: unique identifier of the object to be retrieved
*
* @kbs_key: buffer which will contain the output key
*/
int kmipw_get(char *id, char *kbs_key) {
    log_fp = configure_logger();
    if (log_fp == NULL) {
        printf("Failed to configure logger\n");
        return RESULT_FAILED;
    }
    log_info("kmipw_get called");
    log_debug("get key for id: %s", id);

    SSL_CTX *ctx = NULL;
    BIO *bio = NULL;
    bio = initialize_tls_connection(ctx);
    if(bio == NULL)
    {
        log_error("BIO_new_ssl_connect failed");
        ERR_print_errors_fp(log_fp);
        fclose(log_fp);
        return RESULT_FAILED;
    }
    /* Set up the KMIP context. */
    KMIP kmip_ctx = {0};
    kmip_init(&kmip_ctx, NULL, 0, KMIP_2_0);

    char *key = NULL;
    int key_size = 0;
    size_t id_size = kmip_strnlen_s(id, 50);

    /* Send the request message. */
    int result = kmip_bio_get_symmetric_key_with_context(&kmip_ctx, bio, id, id_size, &key, &key_size);

    free_tls_connection(bio, ctx);

    /* Handle the response results. */
    if(result < RESULT_SUCCESS)
    {
        log_error("An error occurred while retrieving the symmetric key.");
        log_error("Error Code: %d", result);
        kmip_print_error_string(log_fp, result);
        log_error("Context Error: %s", kmip_ctx.error_message);
        log_error("Stack trace:");
        kmip_print_stack_trace(log_fp, &kmip_ctx);
    }
    else if(result >= RESULT_SUCCESS)
    {
        log_info("The KMIP operation was executed with no errors.");
        log_info("Result: ");
        kmip_print_result_status_enum(log_fp, result);

        if(result == KMIP_STATUS_SUCCESS)
        {
            log_debug("Symmetric Key ID: %s", id);
            log_debug("Symmetric Key Size: %d bits", key_size * 8);
            log_debug("Symmetric Key: ");
            kmip_print_buffer(log_fp, key, key_size);
        }
    }

    kmip_memset(kbs_key, 0, key_size);
    kmip_memcpy(NULL, kbs_key, key, key_size);

    if(key != NULL)
    {
        kmip_memset(key, 0, key_size);
        kmip_free(NULL, key);
    }
 
    /* Clean up the KMIP context and return the results. */
    fclose(log_fp);
    kmip_destroy(&kmip_ctx);
    return result;
}
