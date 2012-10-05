#ifndef _LIB_CONFIG_CONFIG_H
#define _LIB_CONFIG_CONFIG_H


#include <inttypes.h>
#include <stdbool.h>

#include "configlib/configlib.h"


enum config_key {
    CONFIG_ROOT_DIR,
    CONFIG_RPKI_PORT,
    CONFIG_DATABASE,
    CONFIG_DATABASE_USER,
    CONFIG_DATABASE_PASSWORD,
    CONFIG_DATABASE_ROOT_PASSWORD,
    CONFIG_DATABASE_DSN,
    CONFIG_DOWNLOAD_CONCURRENCY,
    CONFIG_RPKI_RTR_RETENTION_HOURS,
    CONFIG_RPKI_ALLOW_STALE_VALIDATION_CHAIN,
    CONFIG_RPKI_ALLOW_NO_MANIFEST,
    CONFIG_RPKI_ALLOW_STALE_CRL,
    CONFIG_RPKI_ALLOW_STALE_MANIFEST,
    CONFIG_RPKI_ALLOW_NOT_YET,
    CONFIG_RPKI_EXTRA_PUBLICATION_POINTS,
    CONFIG_TEMPLATE_CA_CERT,
    CONFIG_TEMPLATE_EE_CERT,
    CONFIG_TEMPLATE_CRL,
    CONFIG_TEMPLATE_MANIFEST,
    CONFIG_TEMPLATE_ROA,

    CONFIG_NUM_OPTIONS
};

CONFIG_GET_HELPER(CONFIG_ROOT_DIR, char)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_PORT, uint16_t)
CONFIG_GET_HELPER(CONFIG_DATABASE, char)
CONFIG_GET_HELPER(CONFIG_DATABASE_USER, char)
CONFIG_GET_HELPER(CONFIG_DATABASE_PASSWORD, char)
CONFIG_GET_HELPER(CONFIG_DATABASE_ROOT_PASSWORD, char)
CONFIG_GET_HELPER(CONFIG_DATABASE_DSN, char)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_DOWNLOAD_CONCURRENCY, size_t)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_RTR_RETENTION_HOURS, size_t)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_ALLOW_STALE_VALIDATION_CHAIN, bool)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_ALLOW_NO_MANIFEST, bool)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_ALLOW_STALE_CRL, bool)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_ALLOW_STALE_MANIFEST, bool)
CONFIG_GET_HELPER_DEREFERENCE(CONFIG_RPKI_ALLOW_NOT_YET, bool)
CONFIG_GET_ARRAY_HELPER(CONFIG_RPKI_EXTRA_PUBLICATION_POINTS, char)
CONFIG_GET_HELPER(CONFIG_TEMPLATE_CA_CERT, char)
CONFIG_GET_HELPER(CONFIG_TEMPLATE_EE_CERT, char)
CONFIG_GET_HELPER(CONFIG_TEMPLATE_CRL, char)
CONFIG_GET_HELPER(CONFIG_TEMPLATE_MANIFEST, char)
CONFIG_GET_HELPER(CONFIG_TEMPLATE_ROA, char)



/**
 * Wrapper around config_load() with rpstir-specific data.
 */
bool my_config_load(
    );


#endif
