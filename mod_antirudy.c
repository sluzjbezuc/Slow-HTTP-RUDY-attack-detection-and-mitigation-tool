#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_connection.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_hash.h"
#include "apr_thread_mutex.h"
#include "apr_strings.h"
#include "apr_time.h"
#include "util_filter.h"

module AP_MODULE_DECLARE_DATA antirudy_module;

#define DEFAULT_MAX_SLOW_CONNECTIONS 10
#define DEFAULT_MIN_DATA_RATE 100  // bytes per second
#define DEFAULT_MAX_CONTENT_LENGTH 1048576  // 1 MB

typedef struct {
    int max_slow_connections;
    int min_data_rate;
    int max_content_length;
} antirudy_config;

typedef struct {
    apr_time_t start_time;
    apr_off_t bytes_received;
} conn_info;

// Global hash table and mutex to store connection info per IP
static apr_hash_t *ip_connections = NULL;
static apr_thread_mutex_t *ip_mutex = NULL;

// Function to create server configuration
static void *create_antirudy_server_config(apr_pool_t *p, server_rec *s) {
    antirudy_config *config = apr_pcalloc(p, sizeof(antirudy_config));
    config->max_slow_connections = DEFAULT_MAX_SLOW_CONNECTIONS;
    config->min_data_rate = DEFAULT_MIN_DATA_RATE;
    config->max_content_length = DEFAULT_MAX_CONTENT_LENGTH;
    return config;
}

// Directive handlers
static const char *set_max_slow_connections(cmd_parms *cmd, void *cfg, const char *arg) {
    antirudy_config *config = ap_get_module_config(cmd->server->module_config, &antirudy_module);
    config->max_slow_connections = atoi(arg);
    return NULL;
}

static const char *set_min_data_rate(cmd_parms *cmd, void *cfg, const char *arg) {
    antirudy_config *config = ap_get_module_config(cmd->server->module_config, &antirudy_module);
    config->min_data_rate = atoi(arg);
    return NULL;
}

static const char *set_max_content_length(cmd_parms *cmd, void *cfg, const char *arg) {
    antirudy_config *config = ap_get_module_config(cmd->server->module_config, &antirudy_module);
    config->max_content_length = atoi(arg);
    return NULL;
}

// Configuration directives
static const command_rec antirudy_directives[] = {
    AP_INIT_TAKE1("AntiRudyMaxSlowConnections", set_max_slow_connections, NULL, RSRC_CONF, "Maximum number of slow connections from a single IP"),
    AP_INIT_TAKE1("AntiRudyMinDataRate", set_min_data_rate, NULL, RSRC_CONF, "Minimum data rate in bytes per second"),
    AP_INIT_TAKE1("AntiRudyMaxContentLength", set_max_content_length, NULL, RSRC_CONF, "Maximum allowed Content-Length value"),
    {NULL}
};

// Function to log suspicious activity
static void log_attack(request_rec *r, const char *client_ip) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Possible Slow HTTP POST attack from %s", client_ip);
}

// Input filter to count bytes read
static apr_status_t antirudy_input_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {
    apr_status_t rv;
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    antirudy_config *config = ap_get_module_config(r->server->module_config, &antirudy_module);

    // Pass the call to the next filter in the chain
    rv = ap_get_brigade(f->next, bb, mode, block, readbytes);

    if (rv != APR_SUCCESS) {
        return rv;
    }

    apr_thread_mutex_lock(ip_mutex);

    const char *client_ip = c->client_ip;
    conn_info *info = apr_hash_get(ip_connections, client_ip, APR_HASH_KEY_STRING);
    if (!info) {
        info = apr_pcalloc(c->pool, sizeof(conn_info));
        info->start_time = apr_time_now();
        info->bytes_received = 0;
        apr_hash_set(ip_connections, apr_pstrdup(c->pool, client_ip), APR_HASH_KEY_STRING, info);
    }

    // Count the bytes in the bucket brigade
    apr_bucket *b = NULL;
    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_EOS(b)) {
            // End of stream bucket
            break;
        }

        const char *data;
        apr_size_t len;
        rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (rv == APR_SUCCESS) {
            info->bytes_received += len;
        }
    }

    // Calculate data rate
    apr_time_t now = apr_time_now();
    apr_interval_time_t time_diff = now - info->start_time;
    double elapsed_seconds = apr_time_as_msec(time_diff) / 1000.0;
    double rate = info->bytes_received / (elapsed_seconds + 1);

    // Detection logic
    if (rate < config->min_data_rate && elapsed_seconds > 5) {
        // Possible slow HTTP POST attack detected
        log_attack(r, client_ip);
    }

    // Clean up old entries
    if (elapsed_seconds > 60) {
        apr_hash_set(ip_connections, client_ip, APR_HASH_KEY_STRING, NULL);
    }

    apr_thread_mutex_unlock(ip_mutex);

    return APR_SUCCESS;
}

// The main detection function
static int antirudy_pre_read_request(request_rec *r, conn_rec *c) {
    // Initialize hash table and mutex if not already done
    if (!ip_connections) {
        apr_pool_t *pool = r->server->process->pool;
        apr_thread_mutex_create(&ip_mutex, APR_THREAD_MUTEX_DEFAULT, pool);
        ip_connections = apr_hash_make(pool);
    }

    // Add our input filter
    ap_add_input_filter("ANTIRUDY_IN", NULL, r, c);

    return DECLINED;
}

// Register hooks and filters
static void register_hooks(apr_pool_t *pool) {
    ap_register_input_filter("ANTIRUDY_IN", antirudy_input_filter, NULL, AP_FTYPE_RESOURCE);
    ap_hook_pre_read_request(antirudy_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);
}

// Module declaration
module AP_MODULE_DECLARE_DATA antirudy_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                            // create per-dir config structures
    NULL,                            // merge per-dir config structures
    create_antirudy_server_config,   // create per-server config structures
    NULL,                            // merge per-server config structures
    antirudy_directives,             // configuration directives
    register_hooks                   // register hooks
};
