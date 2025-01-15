#ifndef MOD_ANTIRUDY_H
#define MOD_ANTIRUDY_H

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "apr_file_io.h"
#include "apr_strings.h"

/* 
 * We'll import mod_http_collector.h to use get_request_metrics() and get_concurrency().
 * Make sure your Apache installation can locate "mod_http_collector.h".
 */
#include "mod_http_collector.h"

/*
 * Structure to hold per-server configuration for mod_antirudy.
 * - data_rate_threshold: minimal allowed data transfer rate [bytes/sec]
 * - max_content_length:  maximum "legitimate" Content-Length [bytes]
 * - max_concurrent_conns: maximum allowed concurrent connections per IP 
 * - log_file_path: path to dedicated AntiRudy log file
 * - log_file:       open handle to the above log file
 */
typedef struct {
    double      data_rate_threshold;
    apr_off_t   max_content_length;
    int         max_concurrent_conns;
    const char *log_file_path;
    apr_file_t *log_file;  /* For custom logging */
} antirudy_server_config_t;

/*
 * Export the module's symbol. 
 * Ensures that other code can reference "antirudy_module".
 */
extern module AP_MODULE_DECLARE_DATA antirudy_module;

#endif /* MOD_ANTIRUDY_H */
