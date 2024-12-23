#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "apr_hash.h"
#include "apr_thread_mutex.h"
#include "apr_strings.h"
#include "util_time.h"

/* Structure to store client metrics */
typedef struct {
    const char *ip_address;
    const char *request_method;
    const char *user_agent;
    apr_time_t request_initiation_time;
    apr_time_t request_completion_time;
    apr_off_t content_length;
    apr_off_t bytes_received;
    apr_time_t connection_duration;
    double data_transfer_rate;
    int active_connections;
} client_metrics_t;

/* Global variables */
static apr_hash_t *client_metrics_table;
static apr_thread_mutex_t *table_mutex;
static int test_mode = 0;

/* Helper function to log client metrics */
static void log_client_metrics(request_rec *r, client_metrics_t *metrics) {
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, 
        "mod_http_collector metrics: "
        "IP=%s, Method=%s, User-Agent=%s, ReqTime=%ld, "
        "CompletionTime=%ld, ContentLength=%ld, BytesReceived=%ld, "
        "ConnectionDuration=%ldms, DataRate=%.2fBps, ActiveConnections=%d",
        metrics->ip_address, metrics->request_method, metrics->user_agent,
        metrics->request_initiation_time, metrics->request_completion_time,
        metrics->content_length, metrics->bytes_received,
        metrics->connection_duration, metrics->data_transfer_rate,
        metrics->active_connections);
}

/* Hook: Log phase to capture completion time */
static int http_collector_log_phase(request_rec *r) {
    if (!r->connection || !r->connection->client_ip) {
        return DECLINED;
    }

    const char *client_ip = r->connection->client_ip;

    /* Lock the table */
    apr_thread_mutex_lock(table_mutex);

    /* Retrieve metrics for this client IP */
    client_metrics_t *metrics = apr_hash_get(client_metrics_table, client_ip, APR_HASH_KEY_STRING);
    if (metrics) {
        metrics->request_completion_time = apr_time_now();
        metrics->connection_duration = 
            (apr_time_as_msec(metrics->request_completion_time) - 
             apr_time_as_msec(metrics->request_initiation_time));

        /* Include response size in BytesTransferred for GET */
        if (!strcasecmp(r->method, "GET")) {
            metrics->bytes_received += r->bytes_sent;
        }

        /* For POST, ensure headers and body are accounted for */
        if (!strcasecmp(r->method, "POST")) {
            const char *content_length_str = apr_table_get(r->headers_in, "Content-Length");
            metrics->bytes_received = content_length_str ? apr_atoi64(content_length_str) : 0;
            metrics->bytes_received += r->header_only ? 0 : r->bytes_sent;
        }

        /* Accurate DataRate calculation (duration in seconds) */
        if (metrics->connection_duration > 0) {
            double duration_in_seconds = metrics->connection_duration / 1000.0; // Convert ms to seconds
            if (duration_in_seconds > 0) {
                metrics->data_transfer_rate = metrics->bytes_received / duration_in_seconds;
            } else {
                metrics->data_transfer_rate = 0.0; // Avoid division by zero
            }
        } else {
            metrics->data_transfer_rate = 0.0; // No valid duration
        }

        /* Log in test mode */
        if (test_mode) {
            log_client_metrics(r, metrics);
        }
    }

    /* Unlock the table */
    apr_thread_mutex_unlock(table_mutex);

    return DECLINED;
}

/* Hook: Process each request */
static int http_collector_handler(request_rec *r) {
    if (!r->connection || !r->connection->client_ip) {
        return DECLINED;
    }

    const char *client_ip = r->connection->client_ip;
    apr_time_t now = apr_time_now();

    /* Lock the table */
    apr_thread_mutex_lock(table_mutex);

    /* Get or create metrics for this client IP */
    client_metrics_t *metrics = apr_hash_get(client_metrics_table, client_ip, APR_HASH_KEY_STRING);
    if (!metrics) {
        metrics = apr_pcalloc(r->pool, sizeof(client_metrics_t));
        metrics->ip_address = apr_pstrdup(r->pool, client_ip);
        apr_hash_set(client_metrics_table, metrics->ip_address, APR_HASH_KEY_STRING, metrics);
    }

    /* Update metrics */
    metrics->request_method = r->method ? apr_pstrdup(r->pool, r->method) : "UNKNOWN";
    metrics->user_agent = apr_table_get(r->headers_in, "User-Agent");
    metrics->request_initiation_time = now;

    /* Content-Length header for POST requests */
    const char *content_length_str = apr_table_get(r->headers_in, "Content-Length");
    metrics->content_length = content_length_str ? apr_atoi64(content_length_str) : 0;

    /* Unlock the table */
    apr_thread_mutex_unlock(table_mutex);

    return DECLINED; // Let other handlers process the request
}

/* Directive: Enable or disable test mode */
static const char *set_test_mode(cmd_parms *cmd, void *cfg, const char *arg) {
    if (!strcasecmp(arg, "on")) {
        test_mode = 1;
    } else if (!strcasecmp(arg, "off")) {
        test_mode = 0;
    } else {
        return "Valid values for TestMode are 'on' or 'off'";
    }
    return NULL;
}

/* Command table */
static const command_rec http_collector_cmds[] = {
    AP_INIT_TAKE1("TestMode", set_test_mode, NULL, RSRC_CONF, "Enable or disable test mode"),
    { NULL }
};

/* Hook registration */
static void http_collector_register_hooks(apr_pool_t *p) {
    apr_pool_t *pool;
    apr_pool_create(&pool, NULL);
    client_metrics_table = apr_hash_make(pool);
    apr_thread_mutex_create(&table_mutex, APR_THREAD_MUTEX_DEFAULT, pool);

    ap_hook_log_transaction(http_collector_log_phase, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(http_collector_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Module declaration */
module AP_MODULE_DECLARE_DATA http_collector_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                        /* Per-directory configuration handler */
    NULL,                        /* Merge handler for per-directory configurations */
    NULL,                        /* Per-server configuration handler */
    NULL,                        /* Merge handler for per-server configurations */
    http_collector_cmds,         /* Command handlers */
    http_collector_register_hooks /* Hook registration */
};
