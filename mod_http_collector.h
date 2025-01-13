#ifndef MOD_HTTP_COLLECTOR_H
#define MOD_HTTP_COLLECTOR_H

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"            // For logging macros and functions
#include "apr_strings.h"         // For apr_pstrdup and apr_cpystrn
#include "apr_thread_mutex.h"
#include "apr_shm.h"
#include "apr_time.h"

/* Maximum length for IP address strings (supports IPv6) */
#define IP_ADDRESS_MAX_LEN 46

/* Maximum number of clients to track */
#define MAX_CLIENTS 1024

/* Structure to hold per-client concurrency data */
typedef struct {
    char ip_address[IP_ADDRESS_MAX_LEN];
    int active_connections;
} concurrency_entry_t;

/* Structure for shared memory to track concurrency across processes */
typedef struct {
    apr_thread_mutex_t *table_mutex;
    concurrency_entry_t clients[MAX_CLIENTS];
} concurrency_shm_t;

/* Structure to hold request-specific metrics */
typedef struct {
    const char *ip_address;
    const char *request_method;
    const char *user_agent;
    apr_time_t request_initiation_time;
    apr_time_t request_completion_time;
    apr_off_t content_length;
    apr_off_t bytes_received;
    double data_transfer_rate;       /* bytes per second */
    apr_time_t connection_duration;  /* in milliseconds */
} request_metrics_t;

/* External declaration of the mod_http_collector module */
extern module AP_MODULE_DECLARE_DATA http_collector_module;

/* Function to retrieve the current concurrency for a given IP */
int get_concurrency(const char *ip);

#endif /* MOD_HTTP_COLLECTOR_H */
