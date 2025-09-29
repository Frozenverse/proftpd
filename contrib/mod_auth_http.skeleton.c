/*
 * ProFTPD - mod_auth_http
 * Copyright (c) 2024 ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 */

/* HTTP Authentication module for ProFTPD
 *
 * This module provides authentication against HTTP/HTTPS endpoints.
 */

#include "conf.h"
#include "privs.h"

#include <curl/curl.h>

#define MOD_AUTH_HTTP_VERSION "mod_auth_http/1.0"

module auth_http_module;

static int auth_http_engine = FALSE;
static char *auth_http_url = NULL;
static int auth_http_timeout = 10;
static char *auth_http_method = "POST";
static array_header *auth_http_headers = NULL;
static char *auth_http_user_param = "username";
static char *auth_http_pass_param = "password";
static int auth_http_success_code = 200;
static char *auth_http_user_field = NULL;
static char *auth_http_group_field = NULL;
static int auth_http_cache_time = 0;
static int auth_http_ssl_verify = TRUE;

static pool *auth_http_pool = NULL;
static pr_table_t *auth_http_cache = NULL;

/* Response buffer structure */
struct response_buffer {
  char *data;
  size_t size;
  size_t used;
};

/* Configuration handlers */

MODRET set_authhttpengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

MODRET set_authhttpurl(cmd_rec *cmd) {
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

MODRET set_authhttptimeout(cmd_rec *cmd) {
  config_rec *c;
  int timeout;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  timeout = atoi(cmd->argv[1]);
  if (timeout < 1 || timeout > 300) {
    CONF_ERROR(cmd, "timeout must be between 1 and 300 seconds");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

MODRET set_authhttpmethod(cmd_rec *cmd) {
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "POST") != 0 &&
      strcasecmp(cmd->argv[1], "GET") != 0) {
    CONF_ERROR(cmd, "method must be either POST or GET");
  }

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

MODRET set_authhttpheaders(cmd_rec *cmd) {
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  c->flags |= CF_MERGEDOWN_MULTI;

  return PR_HANDLED(cmd);
}

/* HTTP client functions */

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t real_size = size * nmemb;
  struct response_buffer *resp = (struct response_buffer *)userp;

  if (resp->used + real_size + 1 > resp->size) {
    size_t new_size = resp->size * 2;
    if (new_size < resp->used + real_size + 1) {
      new_size = resp->used + real_size + 1;
    }

    char *new_data = realloc(resp->data, new_size);
    if (!new_data) {
      pr_log_debug(DEBUG0, MOD_AUTH_HTTP_VERSION ": memory allocation failed");
      return 0;
    }

    resp->data = new_data;
    resp->size = new_size;
  }

  memcpy(&(resp->data[resp->used]), contents, real_size);
  resp->used += real_size;
  resp->data[resp->used] = '\0';

  return real_size;
}

static int auth_http_request(const char *username, const char *password,
    char **response_out) {
  CURL *curl;
  CURLcode res;
  struct response_buffer resp = {0};
  char *post_data = NULL;
  int result = -1;
  long http_code = 0;
  struct curl_slist *headers = NULL;

  curl = curl_easy_init();
  if (!curl) {
    pr_log_debug(DEBUG0, MOD_AUTH_HTTP_VERSION ": failed to initialize curl");
    return -1;
  }

  /* Prepare response buffer */
  resp.size = 4096;
  resp.data = malloc(resp.size);
  if (!resp.data) {
    curl_easy_cleanup(curl);
    return -1;
  }
  resp.used = 0;

  /* Set URL */
  curl_easy_setopt(curl, CURLOPT_URL, auth_http_url);

  /* Set timeout */
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, auth_http_timeout);

  /* Set SSL verification */
  if (!auth_http_ssl_verify) {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  }

  /* Set method and data */
  if (strcasecmp(auth_http_method, "POST") == 0) {
    size_t post_len = strlen(auth_http_user_param) + strlen(username) +
                     strlen(auth_http_pass_param) + strlen(password) + 10;
    post_data = malloc(post_len);
    if (post_data) {
      snprintf(post_data, post_len, "%s=%s&%s=%s",
               auth_http_user_param, username,
               auth_http_pass_param, password);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    }
  } else {
    /* GET method - append to URL */
    char *url_with_params = NULL;
    size_t url_len = strlen(auth_http_url) + strlen(auth_http_user_param) +
                    strlen(username) + strlen(auth_http_pass_param) +
                    strlen(password) + 10;
    url_with_params = malloc(url_len);
    if (url_with_params) {
      snprintf(url_with_params, url_len, "%s?%s=%s&%s=%s",
               auth_http_url, auth_http_user_param, username,
               auth_http_pass_param, password);
      curl_easy_setopt(curl, CURLOPT_URL, url_with_params);
      free(url_with_params);
    }
  }

  /* Add custom headers if configured */
  if (auth_http_headers) {
    register unsigned int i;
    for (i = 0; i < auth_http_headers->nelts; i++) {
      char *header = ((char **) auth_http_headers->elts)[i];
      headers = curl_slist_append(headers, header);
    }
    if (headers) {
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
  }

  /* Set callback for response */
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

  /* Perform request */
  pr_log_debug(DEBUG3, MOD_AUTH_HTTP_VERSION ": sending auth request for user '%s'",
    username);

  res = curl_easy_perform(curl);

  if (res == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    pr_log_debug(DEBUG3, MOD_AUTH_HTTP_VERSION ": received HTTP code %ld",
      http_code);

    if (http_code == auth_http_success_code) {
      result = 0;
      if (response_out && resp.data) {
        *response_out = strdup(resp.data);
      }
    } else {
      pr_log_debug(DEBUG1, MOD_AUTH_HTTP_VERSION
        ": authentication failed for user '%s' (HTTP %ld)", username, http_code);
    }
  } else {
    pr_log_debug(DEBUG0, MOD_AUTH_HTTP_VERSION ": curl error: %s",
      curl_easy_strerror(res));
  }

  /* Cleanup */
  if (headers) {
    curl_slist_free_all(headers);
  }
  if (post_data) {
    free(post_data);
  }
  if (resp.data) {
    free(resp.data);
  }
  curl_easy_cleanup(curl);

  return result;
}

/* Authentication handlers */

MODRET auth_http_getpwnam(cmd_rec *cmd) {
  struct passwd *pw = NULL;
  const char *username;

  if (!auth_http_engine) {
    return PR_DECLINED(cmd);
  }

  username = cmd->argv[0];

  /* For HTTP auth, we create a virtual user entry */
  pw = pcalloc(auth_http_pool, sizeof(struct passwd));
  pw->pw_name = pstrdup(auth_http_pool, username);
  pw->pw_passwd = pstrdup(auth_http_pool, "*");
  pw->pw_uid = (uid_t) -1;  /* Will be set from response if available */
  pw->pw_gid = (gid_t) -1;
  pw->pw_dir = pstrcat(auth_http_pool, "/home/", username, NULL);
  pw->pw_shell = pstrdup(auth_http_pool, "/bin/false");

  return mod_create_data(cmd, pw);
}

MODRET auth_http_auth(cmd_rec *cmd) {
  const char *username;
  char *response = NULL;
  int result;

  if (!auth_http_engine) {
    return PR_DECLINED(cmd);
  }

  username = cmd->argv[0];

  pr_log_debug(DEBUG5, MOD_AUTH_HTTP_VERSION ": handling auth request for user '%s'",
    username);

  /* Store username for later password check */
  pr_table_add(session.notes, "auth_http_user", pstrdup(session.pool, username), 0);

  return PR_HANDLED(cmd);
}

MODRET auth_http_chkpass(cmd_rec *cmd) {
  const char *username;
  const char *password;
  char *response = NULL;
  int result;

  if (!auth_http_engine) {
    return PR_DECLINED(cmd);
  }

  username = pr_table_get(session.notes, "auth_http_user", NULL);
  if (!username) {
    pr_log_debug(DEBUG2, MOD_AUTH_HTTP_VERSION ": no username found in session");
    return PR_DECLINED(cmd);
  }

  password = cmd->argv[0];

  /* Check cache first if enabled */
  if (auth_http_cache_time > 0 && auth_http_cache) {
    /* Cache implementation would go here */
  }

  /* Make HTTP request */
  result = auth_http_request(username, password, &response);

  if (result == 0) {
    pr_log_debug(DEBUG2, MOD_AUTH_HTTP_VERSION
      ": authentication successful for user '%s'", username);

    /* Parse response for user/group data if configured */
    if (response && (auth_http_user_field || auth_http_group_field)) {
      /* JSON parsing would go here */
    }

    if (response) {
      free(response);
    }

    /* Update cache if enabled */
    if (auth_http_cache_time > 0 && auth_http_cache) {
      /* Cache update would go here */
    }

    return PR_HANDLED(cmd);
  }

  pr_log_debug(DEBUG2, MOD_AUTH_HTTP_VERSION
    ": authentication failed for user '%s'", username);

  return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
}

/* Module initialization */

static int auth_http_init(void) {
  curl_global_init(CURL_GLOBAL_DEFAULT);

  auth_http_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(auth_http_pool, MOD_AUTH_HTTP_VERSION);

  return 0;
}

static int auth_http_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "AuthHTTPEngine", FALSE);
  if (c) {
    auth_http_engine = *((int *) c->argv[0]);
  }

  if (!auth_http_engine) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "AuthHTTPURL", FALSE);
  if (c) {
    auth_http_url = c->argv[0];
  } else if (auth_http_engine) {
    pr_log_pri(PR_LOG_WARNING, MOD_AUTH_HTTP_VERSION
      ": AuthHTTPEngine enabled but no AuthHTTPURL configured");
    auth_http_engine = FALSE;
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "AuthHTTPTimeout", FALSE);
  if (c) {
    auth_http_timeout = *((int *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "AuthHTTPMethod", FALSE);
  if (c) {
    auth_http_method = c->argv[0];
  }

  /* Initialize cache if cache time is set */
  if (auth_http_cache_time > 0) {
    auth_http_cache = pr_table_alloc(auth_http_pool, 0);
  }

  pr_log_debug(DEBUG2, MOD_AUTH_HTTP_VERSION ": module enabled, URL: %s",
    auth_http_url);

  return 0;
}

/* Module tables */

static conftable auth_http_conftab[] = {
  { "AuthHTTPEngine",       set_authhttpengine,       NULL },
  { "AuthHTTPURL",          set_authhttpurl,          NULL },
  { "AuthHTTPTimeout",      set_authhttptimeout,      NULL },
  { "AuthHTTPMethod",       set_authhttpmethod,       NULL },
  { "AuthHTTPHeaders",      set_authhttpheaders,      NULL },
  { NULL }
};

static authtable auth_http_authtab[] = {
  { 0, "getpwnam",  auth_http_getpwnam },
  { 0, "auth",      auth_http_auth },
  { 0, "check",     auth_http_chkpass },
  { 0, NULL, NULL }
};

module auth_http_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "auth_http",

  /* Module configuration handler table */
  auth_http_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  auth_http_authtab,

  /* Module initialization */
  auth_http_init,

  /* Session initialization */
  auth_http_sess_init,

  /* Module version */
  MOD_AUTH_HTTP_VERSION
};