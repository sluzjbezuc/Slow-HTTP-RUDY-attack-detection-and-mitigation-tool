#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "util_time.h"
#include "mod_antirudy.h"

/* -----------------------------------------------------------
 *  Default (example) thresholds for detection
 *  Adjust as you see fit.
 * ----------------------------------------------------------- */
#define DEFAULT_DATA_RATE_THRESHOLD        50.0      /* bytes/sec */
#define DEFAULT_MAX_CONTENT_LENGTH         1048576   /* 1 MB      */
#define DEFAULT_MAX_CONCURRENT_CONNECTIONS 10
#define DEFAULT_ANTIRUDY_LOGFILE          "logs/antirudy.log"

/*
 * Create the per-server config with default values.
 */
static void *antirudy_create_server_config(apr_pool_t *p, server_rec *s)
{
    antirudy_server_config_t *cfg = 
        (antirudy_server_config_t *)apr_pcalloc(p, sizeof(*cfg));

    cfg->data_rate_threshold   = DEFAULT_DATA_RATE_THRESHOLD;
    cfg->max_content_length    = DEFAULT_MAX_CONTENT_LENGTH;
    cfg->max_concurrent_conns  = DEFAULT_MAX_CONCURRENT_CONNECTIONS;
    cfg->log_file_path         = DEFAULT_ANTIRUDY_LOGFILE;
    cfg->log_file              = NULL;

    return cfg;
}

/*
 * Merge server config if you have VirtualHosts. 
 * Here we simply overwrite with the child (vhost) config if set.
 */
static void *antirudy_merge_server_config(apr_pool_t *p, void *basev, void *addv)
{
    antirudy_server_config_t *base = (antirudy_server_config_t *) basev;
    antirudy_server_config_t *add  = (antirudy_server_config_t *) addv;
    antirudy_server_config_t *conf = 
        (antirudy_server_config_t *)apr_pcalloc(p, sizeof(*conf));

    /* For each field, if 'add' config was changed from default, use it, 
       otherwise fallback to base config. */
    conf->data_rate_threshold = (add->data_rate_threshold != DEFAULT_DATA_RATE_THRESHOLD) 
                                    ? add->data_rate_threshold 
                                    : base->data_rate_threshold;

    conf->max_content_length  = (add->max_content_length != DEFAULT_MAX_CONTENT_LENGTH)
                                    ? add->max_content_length
                                    : base->max_content_length;

    conf->max_concurrent_conns= (add->max_concurrent_conns != DEFAULT_MAX_CONCURRENT_CONNECTIONS)
                                    ? add->max_concurrent_conns
                                    : base->max_concurrent_conns;

    conf->log_file_path = (add->log_file_path && strcmp(add->log_file_path, DEFAULT_ANTIRUDY_LOGFILE) != 0)
                                    ? add->log_file_path
                                    : base->log_file_path;

    conf->log_file = NULL;  /* We'll re-open in post_config if needed */
    return conf;
}

/*
 * Configuration Directives
 *   AntiRudyDataRateThreshold <double>
 *   AntiRudyMaxContentLength  <apr_off_t>
 *   AntiRudyMaxConcurrentConnections <int>
 *   AntiRudyLogFile <string>
 *
 * Example usage in httpd.conf:
 *   AntiRudyDataRateThreshold 100
 *   AntiRudyMaxContentLength  10485760
 *   AntiRudyMaxConcurrentConnections 20
 *   AntiRudyLogFile "/var/log/apache2/antirudy.log"
 */

/* Set minimal data rate threshold (bytes/sec) */
static const char *antirudy_set_data_rate(cmd_parms *cmd, void *cfg, const char *arg)
{
    antirudy_server_config_t *conf = 
        (antirudy_server_config_t *)ap_get_module_config(cmd->server->module_config, &antirudy_module);

    conf->data_rate_threshold = atof(arg);
    return NULL;
}

/* Set maximum content length (bytes) considered legitimate */
static const char *antirudy_set_max_content_length(cmd_parms *cmd, void *cfg, const char *arg)
{
    antirudy_server_config_t *conf = 
        (antirudy_server_config_t *)ap_get_module_config(cmd->server->module_config, &antirudy_module);

    conf->max_content_length = (apr_off_t)apr_atoi64(arg);
    return NULL;
}

/* Set maximum concurrent connections allowed per IP before suspicion */
static const char *antirudy_set_max_concurrent_conns(cmd_parms *cmd, void *cfg, const char *arg)
{
    antirudy_server_config_t *conf = 
        (antirudy_server_config_t *)ap_get_module_config(cmd->server->module_config, &antirudy_module);

    conf->max_concurrent_conns = atoi(arg);
    return NULL;
}

/* Set the log file path for AntiRudy logs */
static const char *antirudy_set_logfile(cmd_parms *cmd, void *cfg, const char *arg)
{
    antirudy_server_config_t *conf = 
        (antirudy_server_config_t *)ap_get_module_config(cmd->server->module_config, &antirudy_module);

    conf->log_file_path = arg;
    return NULL;
}

/* Command table for mod_antirudy */
static const command_rec antirudy_cmds[] = {
    AP_INIT_TAKE1("AntiRudyDataRateThreshold",
                  antirudy_set_data_rate,
                  NULL,
                  RSRC_CONF,
                  "Minimal average data rate (bytes/sec) below which suspicion of a slow attack is raised."),
    AP_INIT_TAKE1("AntiRudyMaxContentLength",
                  antirudy_set_max_content_length,
                  NULL,
                  RSRC_CONF,
                  "Max Content-Length (bytes) considered normal. Exceeding triggers suspicion."),
    AP_INIT_TAKE1("AntiRudyMaxConcurrentConnections",
                  antirudy_set_max_concurrent_conns,
                  NULL,
                  RSRC_CONF,
                  "Max concurrent connections per IP allowed before suspicion is raised."),
    AP_INIT_TAKE1("AntiRudyLogFile",
                  antirudy_set_logfile,
                  NULL,
                  RSRC_CONF,
                  "Path to dedicated AntiRudy log file"),
    { NULL }
};

/*
 * Utility: log a single line to the dedicated AntiRudy log file.
 * Timestamps suspicious activity, IP address, suspicion level, etc.
 */
static void antirudy_log_suspicion(request_rec *r,
                                   antirudy_server_config_t *cfg,
                                   const char *level,
                                   const char *reason,
                                   double rate,
                                   apr_off_t cl,
                                   int concurrency)
{
    if (!cfg->log_file) {
        return;  /* If no file handle, nothing to do. */
    }
    /* Format a timestamp. Note: For brevity, using apr_ctime here. */
    char time_str[APR_CTIME_LEN];
    apr_ctime(time_str, apr_time_now());

    apr_file_printf(cfg->log_file,
        "[%s] [client %s] [level: %s] [rate: %.2f Bps] [cl: %" APR_OFF_T_FMT "] "
        "[concurrency: %d] reason=\"%s\"\n",
        time_str,
        r->connection->client_ip ? r->connection->client_ip : "unknown",
        level, rate, cl, concurrency, reason
    );
}

/*
 * post_config hook: open our log file, etc.
 */
static int antirudy_post_config(apr_pool_t *pconf,
                                apr_pool_t *plog,
                                apr_pool_t *ptemp,
                                server_rec *s)
{
    /* We may have multiple server_recs in a server chain. We'll iterate. */
    for (server_rec *sr = s; sr != NULL; sr = sr->next) {
        antirudy_server_config_t *cfg = 
            (antirudy_server_config_t *)ap_get_module_config(sr->module_config, &antirudy_module);

        if (cfg->log_file_path && *cfg->log_file_path) {
            apr_status_t rv = apr_file_open(&cfg->log_file,
                                            cfg->log_file_path,
                                            APR_WRITE | APR_APPEND | APR_CREATE,
                                            APR_OS_DEFAULT,
                                            pconf);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, sr,
                             "mod_antirudy: Failed to open log file '%s'",
                             cfg->log_file_path);
                /* If we fail to open, set to NULL so we don't try to write. */
                cfg->log_file = NULL;
            }
        }
    }
    return OK;
}

/*
 * The core detection logic:
 *  - We run it in the log_transaction hook so that mod_http_collector 
 *    has already finalized the request metrics (including data_transfer_rate).
 *  - We only do detection if the request method is POST (common for slow-loris style).
 *  - We compare metrics to thresholds. 
 *  - We log suspicion or detection events to the dedicated log file.
 */
static int antirudy_log_transaction(request_rec *r)
{
    /* Only focus on successful requests that used POST method. */
    if (r->method_number != M_POST) {
        return DECLINED;
    }

    /* Retrieve the request metrics from mod_http_collector. */
    request_metrics_t *rm = get_request_metrics(r);
    if (!rm) {
        return DECLINED; 
    }

    /* Get concurrency from mod_http_collector. */
    int concurrency = get_concurrency(rm->ip_address ? rm->ip_address : "");

    /* Retrieve AntiRudy config from the server_rec. */
    antirudy_server_config_t *cfg = 
        (antirudy_server_config_t *)ap_get_module_config(r->server->module_config, &antirudy_module);

    double rate        = rm->data_transfer_rate;  /* bytes/sec */
    apr_off_t cl       = rm->content_length;
    int max_conns      = cfg->max_concurrent_conns;
    double rate_thresh = cfg->data_rate_threshold;
    apr_off_t max_cl   = cfg->max_content_length;

    /* 
     * Example "signatures" or detection rules (simplistic):
     * 1. If concurrency > max_concurrent_conns, flag as "Possible slow POST" 
     *    or "Detected slow POST" if concurrency is well above threshold.
     * 2. If data rate < rate_thresh, suspect a slow-loris style POST.
     * 3. If content_length > max_cl, suspect an abnormally large upload. 
     * 
     * We'll produce different suspicion levels depending on severity. 
     */
    int suspicious = 0;
    const char *suspicion_level = NULL;
    const char *reason = "";

    /* Check concurrency. */
    if (concurrency > max_conns && concurrency <= (max_conns * 2)) {
        suspicious = 1;
        suspicion_level = "Possible slow HTTP POST attack";
        reason = "Concurrency above normal threshold";
    }
    else if (concurrency > (max_conns * 2)) {
        suspicious = 2;
        suspicion_level = "Detected Slow HTTP POST attack";
        reason = "Concurrency significantly exceeded threshold";
    }

    /* Check data rate. */
    if (rate > 0 && rate < rate_thresh && suspicious < 2) {
        if (suspicious == 1) {
            /* Already flagged concurrency => escalate to stronger detection */
            suspicious = 2;
            suspicion_level = "Detected Slow HTTP POST attack";
            reason = apr_pstrcat(r->pool, reason, " & data rate below threshold", NULL);
        }
        else {
            suspicious = 1;
            suspicion_level = "Possible slow HTTP POST attack";
            reason = "Data rate below threshold";
        }
    }

    /* Check content length. */
    if (cl > max_cl && suspicious < 2) {
        if (suspicious == 1) {
            /* Already flagged => escalate to stronger detection */
            suspicious = 2;
            suspicion_level = "Detected Slow HTTP POST attack";
            reason = apr_pstrcat(r->pool, reason, " & content length too large", NULL);
        }
        else {
            suspicious = 1;
            suspicion_level = "Possible slow HTTP POST attack";
            reason = "Content length too large";
        }
    }

    /* If suspicious > 0, log it to our custom log file. */
    if (suspicious > 0) {
        antirudy_log_suspicion(r, cfg, suspicion_level, reason, rate, cl, concurrency);
    }

    return DECLINED;  /* let Apache proceed with normal logging as well */
}

/*
 * Register hooks
 */
static void antirudy_register_hooks(apr_pool_t *p)
{
    /*
     * We open log file in post_config 
     * (once the config directives have been parsed).
     */
    ap_hook_post_config(antirudy_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    /*
     * We do detection in the log_transaction phase,
     * after mod_http_collector has already done its final metrics.
     */
    ap_hook_log_transaction(antirudy_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
 * Module definition
 */
module AP_MODULE_DECLARE_DATA antirudy_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                                /* per-directory config creator */
    NULL,                                /* merge per-directory config */
    antirudy_create_server_config,       /* per-server config creator */
    antirudy_merge_server_config,        /* merge per-server config */
    antirudy_cmds,                       /* command table */
    antirudy_register_hooks              /* register hooks */
};
