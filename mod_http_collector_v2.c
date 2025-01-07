#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_thread_mutex.h"
#include "apr_shm.h"
#include "util_filter.h"
#include "util_time.h"


extern module AP_MODULE_DECLARE_DATA http_collector_module;

int test_mode = 0;

/* ------------------------------------------------------
 *     SHARED MEMORY FOR CROSS-PROCESS CONCURRENCY
 *    (Tracks how many requests are currently in progress
 *     for each IP address).
 * ------------------------------------------------------ */
#define MAX_CLIENTS 1024

typedef struct {
    char ip_address[64];
    int  active_connections;  
} concurrency_entry_t;

typedef struct {
    apr_thread_mutex_t *table_mutex;
    concurrency_entry_t clients[MAX_CLIENTS];
} concurrency_shm_t;

// Global handles for shared memory and concurrency data
static apr_shm_t        *g_shm         = NULL;
static concurrency_shm_t *g_concurrency = NULL;

// Utility: strip trailing ":port" from an IP string
static const char* strip_port_suffix(apr_pool_t *p, const char *ip_with_port)
{
    char *ip_no_port = apr_pstrdup(p, ip_with_port);
    char *colon = strrchr(ip_no_port, ':');
    if (colon) {
        /* If there's a ']', ensure colon is after it (for IPv6). */
        char *maybe_ipv6_bracket = strrchr(ip_no_port, ']');
        if (!maybe_ipv6_bracket || maybe_ipv6_bracket < colon) {
            *colon = '\0';
        }
    }
    return ip_no_port;
}

/* Find or create concurrency entry for IP in the fixed array */
static concurrency_entry_t* find_or_create_concurrency_entry(const char *ip)
{
    int i;
    concurrency_entry_t *empty_slot = NULL;

    for (i = 0; i < MAX_CLIENTS; i++) {
        
        if (g_concurrency->clients[i].ip_address[0] == '\0') {
            if (!empty_slot) {
                empty_slot = &g_concurrency->clients[i];
            }
        }
        
        else if (strcmp(g_concurrency->clients[i].ip_address, ip) == 0) {
            return &g_concurrency->clients[i];
        }
    }
    /* Use the first empty slot if we didn't find a match. */
    if (empty_slot) {
        apr_cpystrn(empty_slot->ip_address, ip, sizeof(empty_slot->ip_address));
        empty_slot->active_connections = 0;
        return empty_slot;
    }
    return NULL; /* Table full */
}

/* 
 * post_config hook: create shared memory, initialize concurrency data 
 * (called once in the parent process before forking child processes).
 */
static int http_collector_post_config(apr_pool_t *pconf,
                                      apr_pool_t *plog,
                                      apr_pool_t *ptemp,
                                      server_rec *s)
{
    apr_size_t shm_size = sizeof(*g_concurrency);
    apr_status_t rv;

    // Create the shared memory
    rv = apr_shm_create(&g_shm, shm_size, NULL, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "mod_http_collector: Failed to create shared memory");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    // Get the pointer to base address
    g_concurrency = apr_shm_baseaddr_get(g_shm);
    if (!g_concurrency) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                     "mod_http_collector: Failed to get SHM base address");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    memset(g_concurrency, 0, shm_size);

    /* Create a cross-process mutex (if needed truly cross-process,
       you might use apr_global_mutex_create). */
    rv = apr_thread_mutex_create(&g_concurrency->table_mutex,
                                 APR_THREAD_MUTEX_DEFAULT,
                                 pconf);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "mod_http_collector: Failed to create concurrency mutex");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_http_collector: Shared memory initialized (%zu bytes)",
                 (size_t)shm_size);

    return OK;
}

// Observed per-request metrics
typedef struct {
    const char *ip_address;
    const char *request_method;
    const char *user_agent;
    apr_time_t  request_initiation_time;
    apr_time_t  request_completion_time;
    apr_off_t   content_length;
    apr_off_t   bytes_received;
    apr_time_t  connection_duration; /* ms */
    double      data_transfer_rate;  /* Bps */
} request_metrics_t;


/* 
 * Input filter: count bytes received; if test_mode, log partial updates (tagged [DYNAMIC]).
 */
static apr_status_t http_collector_input_filter(ap_filter_t *f,
                                                apr_bucket_brigade *bb,
                                                ap_input_mode_t mode,
                                                apr_read_type_e block,
                                                apr_off_t readbytes)
{
    request_rec *r = f->r;
    apr_status_t status;

    status = ap_get_brigade(f->next, bb, mode, block, readbytes);
    if (status != APR_SUCCESS) {
        return status;
    }

    apr_size_t len = 0;
    for (apr_bucket *b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        if (APR_BUCKET_IS_EOS(b)) {
            continue;
        }
        const char *data;
        apr_size_t data_len;
        status = apr_bucket_read(b, &data, &data_len, APR_BLOCK_READ);
        if (status != APR_SUCCESS) {
            return status;
        }
        len += data_len;
    }

    /* Update this request's metrics (r->request_config) */
    request_metrics_t *rm = ap_get_module_config(r->request_config, &http_collector_module);
    if (rm) {
        rm->bytes_received += len;

        if (test_mode) {
            /* For partial updates, also show concurrency */
            apr_thread_mutex_lock(g_concurrency->table_mutex);
            concurrency_entry_t *entry = find_or_create_concurrency_entry(rm->ip_address);
            int active_conns = entry ? entry->active_connections : -1;
            apr_thread_mutex_unlock(g_concurrency->table_mutex);

            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                "mod_http_collector [DYNAMIC]: IP=%s, BytesReceived=%" APR_OFF_T_FMT
                ", ContentLength=%" APR_OFF_T_FMT ", ActiveConnections=%d",
                rm->ip_address, rm->bytes_received, rm->content_length, active_conns
            );
        }
    }

    return APR_SUCCESS;
}

/* 
 * Cleanup callback: called when the request pool is destroyed (i.e. end of request),
 * so concurrency is decremented at the *request* level.
 */
static apr_status_t decrement_client_connections(void *data)
{
    request_rec *r = (request_rec *)data;
    if (!r || !r->connection || !r->connection->client_ip) {
        return APR_SUCCESS;
    }

    const char *client_ip = strip_port_suffix(r->pool, r->connection->client_ip);

    apr_thread_mutex_lock(g_concurrency->table_mutex);
    concurrency_entry_t *entry = find_or_create_concurrency_entry(client_ip);
    if (entry && entry->active_connections > 0) {
        entry->active_connections--;
    }
    apr_thread_mutex_unlock(g_concurrency->table_mutex);

    return APR_SUCCESS;
}

// log_phase: finalize request metrics, log them along with current concurrency if test_mode on.

static int http_collector_log_phase(request_rec *r)
{
    if (!r->connection || !r->connection->client_ip) {
        return DECLINED;
    }

    request_metrics_t *rm = ap_get_module_config(r->request_config, &http_collector_module);
    if (!rm) {
        return DECLINED;
    }

    // Mark request completion, calculate duration, data rate
    rm->request_completion_time = apr_time_now();
    rm->connection_duration =
        (apr_time_as_msec(rm->request_completion_time)
         - apr_time_as_msec(r->request_time)); /* or rm->request_initiation_time */

    if (rm->connection_duration > 0) {
        double sec = rm->connection_duration / 1000.0;
        rm->data_transfer_rate = (rm->bytes_received / sec);
    } else {
        rm->data_transfer_rate = 0.0;
    }

    // Retrieve concurrency from shared memory
    int current_concurrency = -1;
    const char *client_ip = rm->ip_address;

    apr_thread_mutex_lock(g_concurrency->table_mutex);
    concurrency_entry_t *entry = find_or_create_concurrency_entry(client_ip);
    if (entry) {
        current_concurrency = entry->active_connections;
    }
    apr_thread_mutex_unlock(g_concurrency->table_mutex);

    // Log final metrics
    if (test_mode) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
            "mod_http_collector [FINAL]: IP=%s, Method=%s, User-Agent=%s, "
            "ActiveConnections=%d, BytesReceived=%" APR_OFF_T_FMT
            ", ContentLength=%" APR_OFF_T_FMT ", Duration=%" APR_TIME_T_FMT "ms, DataRate=%.2fBps",
            rm->ip_address,
            rm->request_method ? rm->request_method : "UNKNOWN",
            rm->user_agent     ? rm->user_agent     : "UNKNOWN",
            current_concurrency,
            rm->bytes_received,
            rm->content_length,
            rm->connection_duration,
            rm->data_transfer_rate
        );
    }

    return DECLINED;
}

/* 
 * post_read_request hook: 
 *  - Set up request_metrics
 *  - Attach input filter
 *  - Increment concurrency
 *  - Register a cleanup on r->pool (end of request => concurrency--)
 */
static int http_collector_post_read_request(request_rec *r)
{
    if (!r->connection || !r->connection->client_ip) {
        return DECLINED;
    }

    const char *client_ip = strip_port_suffix(r->pool, r->connection->client_ip);

    // Metrics stored in request pool
    request_metrics_t *rm = apr_pcalloc(r->pool, sizeof(*rm));
    ap_set_module_config(r->request_config, &http_collector_module, rm);

    rm->ip_address           = client_ip;
    rm->request_method       = (r->method ? apr_pstrdup(r->pool, r->method) : "UNKNOWN");
    rm->user_agent           = apr_table_get(r->headers_in, "User-Agent");
    rm->request_initiation_time = apr_time_now(); /* or r->request_time */
    rm->bytes_received       = 0;

    // Content-Length if present
    const char *cl_header = apr_table_get(r->headers_in, "Content-Length");
    rm->content_length = cl_header ? apr_atoi64(cl_header) : 0;

    // Increment concurrent connections
    apr_thread_mutex_lock(g_concurrency->table_mutex);
    concurrency_entry_t *entry = find_or_create_concurrency_entry(client_ip);
    if (entry) {
        entry->active_connections++;
    }
    apr_thread_mutex_unlock(g_concurrency->table_mutex);

    // Log concurrency updates if test mode on 
    if (test_mode && entry) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
            "mod_http_collector [UPDATED]: IP=%s, Method=%s, ActiveConnections=%d",
            client_ip, rm->request_method, entry->active_connections);
    }

    // Attach input filter to track bytes & partial updates
    ap_add_input_filter("HTTP_COLLECTOR_FILTER", NULL, r, r->connection);

    // register cleanup on r->pool (request pool), so concurrency is decremented once the request ends.
    apr_pool_cleanup_register(r->pool, (void*)r,
                              decrement_client_connections,
                              apr_pool_cleanup_null);

    return DECLINED; /* Let other modules proceed */
}

// Test Mode on|off
static const char *set_test_mode(cmd_parms *cmd, void *cfg, const char *arg)
{
    if (!strcasecmp(arg, "on")) {
        test_mode = 1;
    }
    else if (!strcasecmp(arg, "off")) {
        test_mode = 0;
    }
    else {
        return "Valid values for TestMode are 'on' or 'off'";
    }
    return NULL;
}

// COMMAND TABLE
static const command_rec http_collector_cmds[] = {
    AP_INIT_TAKE1("TestMode", set_test_mode, NULL, RSRC_CONF,
                  "Enable or disable test mode for mod_http_collector"),
    { NULL }
};

// HOOK REGISTRATION 
static void http_collector_register_hooks(apr_pool_t *p)
{
    // Create/attach shared memory in post_config
    ap_hook_post_config(http_collector_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    // Register input filter for reading request body chunks
    ap_register_input_filter("HTTP_COLLECTOR_FILTER",
                             http_collector_input_filter,
                             NULL,
                             AP_FTYPE_RESOURCE);

    // post_read_request: increment concurrency, set up request metrics
    ap_hook_post_read_request(http_collector_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);

    // log_phase: finalize & log metrics
    ap_hook_log_transaction(http_collector_log_phase, NULL, NULL, APR_HOOK_MIDDLE);
}

// MODULE DEFINITION
module AP_MODULE_DECLARE_DATA http_collector_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                        /* per-dir config creator */
    NULL,                        /* merge per-dir configs */
    NULL,                        /* per-server config creator */
    NULL,                        /* merge per-server configs */
    http_collector_cmds,         /* directive handlers */
    http_collector_register_hooks /* register hooks */
};
