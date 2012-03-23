/*
Copyright (C) 2007-2010 Butterfat, LLC (http://butterfat.net)

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Created by bmuller <bmuller@butterfat.net>
*/

#include "mod_auth_openid.h"

extern "C" module AP_MODULE_DECLARE_DATA authopenid_module;


struct modauthopenid_ax_t {
    std::string uri;
    bool required;
    int count;
};
typedef std::map<std::string, modauthopenid_ax_t> modauthopenid_ax_map;

void modauthopenid_ax_map_cleanup(void* ptr) { delete (modauthopenid_ax_map*)ptr ; }


typedef struct {
  char *trust_root;
  const char *cookie_name;
  char *login_page;
  bool enabled;
  bool use_cookie;
  bool secure_cookie;
  apr_array_header_t *trusted;
  apr_array_header_t *distrusted;
  int cookie_lifespan;
  char *server_name;
  char *auth_program;
  char *cookie_path;
  bool use_auth_program;
  modauthopenid_ax_map *attr;
} modauthopenid_config;

typedef struct {
  apr_array_header_t *memcached_addr;
  modauthopenid::memcache::MemCached memcached;
} modauthopenid_server_config;

typedef const char *(*CMD_HAND_TYPE) ();

// determine if a connection is using https - only took 1000 years to figure this one out
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *using_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

static void *create_modauthopenid_config(apr_pool_t *p, char *s) {
  modauthopenid_config *newcfg;
  newcfg = (modauthopenid_config *) apr_pcalloc(p, sizeof(modauthopenid_config));
  newcfg->enabled = false;
  newcfg->use_cookie = true;
  newcfg->secure_cookie = false;
  newcfg->cookie_name = "open_id_session_id";
  newcfg->cookie_path = NULL; 
  newcfg->trusted = apr_array_make(p, 5, sizeof(char *));
  newcfg->distrusted = apr_array_make(p, 5, sizeof(char *));
  newcfg->trust_root = NULL;
  newcfg->cookie_lifespan = 0;
  newcfg->server_name = NULL;
  newcfg->auth_program = NULL;
  newcfg->use_auth_program = false;
  newcfg->attr = new modauthopenid_ax_map;
  apr_pool_cleanup_register(p, (void*)newcfg->attr, (apr_status_t(*)(void *))modauthopenid_ax_map_cleanup, apr_pool_cleanup_null) ;
  return (void *) newcfg;
}

static void *create_modauthopenid_server_config(apr_pool_t *p, server_rec *s) {
  modauthopenid_server_config *newcfg;
  newcfg = (modauthopenid_server_config *) apr_pcalloc(p, sizeof(modauthopenid_server_config));
  newcfg->memcached_addr = apr_array_make(p, 5, sizeof(char *));
  return (void *) newcfg;
}

static const char *set_modauthopenid_cookie_path(cmd_parms *parms, void *mconfig, const char *arg) { 
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig; 
  s_cfg->cookie_path = (char *) arg; 
  return NULL; 
} 

static const char *set_modauthopenid_trust_root(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->trust_root = (char *) arg;
  return NULL;
}

static const char *set_modauthopenid_login_page(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->login_page = (char *) arg;
  return NULL;
}

static const char *set_modauthopenid_cookie_name(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->cookie_name = (char *) arg;
  return NULL;
}

static const char *set_modauthopenid_enabled(cmd_parms *parms, void *mconfig, int flag) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->enabled = (bool) flag;
  return NULL;
}

static const char *set_modauthopenid_usecookie(cmd_parms *parms, void *mconfig, int flag) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->use_cookie = (bool) flag;
  return NULL;
}

static const char *set_modauthopenid_secure_cookie(cmd_parms *parms, void *mconfig, int flag) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->secure_cookie = (bool) flag;
  return NULL;
}

static const char *set_modauthopenid_cookie_lifespan(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->cookie_lifespan = atoi(arg);
  return NULL;
}

static const char *add_modauthopenid_trusted(cmd_parms *cmd, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  *(const char **)apr_array_push(s_cfg->trusted) = arg;
  return NULL;
}

static const char *add_modauthopenid_distrusted(cmd_parms *cmd, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  *(const char **)apr_array_push(s_cfg->distrusted) = arg;
  return NULL;
}

static const char *set_modauthopenid_server_name(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->server_name = (char *) arg;
  return NULL;
} 
 
static const char *set_modauthopenid_auth_program(cmd_parms *parms, void *mconfig, const char *arg) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
  s_cfg->auth_program = (char *) arg;
  s_cfg->use_auth_program = true;
  return NULL;
} 

static const char *set_modauthopenid_attribute_exchange_add(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg2, const char *arg3) {
    modauthopenid_config *s_cfg = (modauthopenid_config *) mconfig;
    std::string alias = std::string(arg1);
    std::string uri = std::string(arg2);
    bool required = true;
    if(arg3) {
	std::string req = std::string(arg3);
	//TODO: are there any other values, that should be interpreted as false?
	required = (req!="false");
    }

    modauthopenid_ax_t attr;
    attr.uri = uri;
    attr.required = required;
    attr.count = 1; //TODO: add support for count > 1
    (*s_cfg->attr)[alias] = attr;
    return NULL;
}

static const char *add_modauthopenid_memcached(cmd_parms *cmd, void *mconfig, const char *arg) {
  modauthopenid_server_config *s_cfg = (modauthopenid_server_config *) ap_get_module_config(cmd->server->module_config, &authopenid_module);
  *(const char **)apr_array_push(s_cfg->memcached_addr) = arg;
  return NULL;
}

static int config_merge(modauthopenid_server_config* s_scfg, server_rec* s) {
  if (s == NULL)
    return OK;
  modauthopenid_server_config *s_cfg = (modauthopenid_server_config *)ap_get_module_config(s->module_config, &authopenid_module);
  *s_cfg = *s_scfg;
  return config_merge(s_scfg, s->next);
}

static void child_init(apr_pool_t* p, server_rec* s) {
  modauthopenid::debug("child_init");
  modauthopenid_server_config *s_cfg = (modauthopenid_server_config *)ap_get_module_config(s->module_config, &authopenid_module);
  if (s_cfg->memcached_addr->nelts != 0)
    s_cfg->memcached = modauthopenid::memcache::MemCached(s_cfg->memcached_addr, p);
  else
    s_cfg->memcached = modauthopenid::memcache::MemCached("localhost", 11211, p);
  config_merge(s_cfg, s->next);
}

static const command_rec mod_authopenid_cmds[] = {
  AP_INIT_TAKE1("AuthOpenIDCookieLifespan", (CMD_HAND_TYPE) set_modauthopenid_cookie_lifespan, NULL, OR_AUTHCFG,
		"AuthOpenIDCookieLifespan <number seconds>"),
  AP_INIT_TAKE1("AuthOpenIDLoginPage", (CMD_HAND_TYPE) set_modauthopenid_login_page, NULL, OR_AUTHCFG,
		"AuthOpenIDLoginPage <url string>"),
  AP_INIT_TAKE1("AuthOpenIDTrustRoot", (CMD_HAND_TYPE) set_modauthopenid_trust_root, NULL, OR_AUTHCFG,
		"AuthOpenIDTrustRoot <trust root to use>"),
  AP_INIT_TAKE1("AuthOpenIDCookieName", (CMD_HAND_TYPE) set_modauthopenid_cookie_name, NULL, OR_AUTHCFG,
		"AuthOpenIDCookieName <name of cookie to use>"),
  AP_INIT_TAKE1("AuthOpenIDCookiePath", (CMD_HAND_TYPE) set_modauthopenid_cookie_path, NULL, OR_AUTHCFG, 
		"AuthOpenIDCookiePath <path of cookie to use>"), 
  AP_INIT_FLAG("AuthOpenIDSecureCookie", (CMD_HAND_TYPE) set_modauthopenid_secure_cookie, NULL, OR_AUTHCFG,
		"AuthOpenIDSecureCookie <On | Off> - use a secure cookie?"),
  AP_INIT_FLAG("AuthOpenIDEnabled", (CMD_HAND_TYPE) set_modauthopenid_enabled, NULL, OR_AUTHCFG,
	       "AuthOpenIDEnabled <On | Off>"),
  AP_INIT_FLAG("AuthOpenIDUseCookie", (CMD_HAND_TYPE) set_modauthopenid_usecookie, NULL, OR_AUTHCFG,
	       "AuthOpenIDUseCookie <On | Off> - use session auth?"),
  AP_INIT_ITERATE("AuthOpenIDTrusted", (CMD_HAND_TYPE) add_modauthopenid_trusted, NULL, OR_AUTHCFG,
		  "AuthOpenIDTrusted <a list of trusted identity providers>"),
  AP_INIT_ITERATE("AuthOpenIDDistrusted", (CMD_HAND_TYPE) add_modauthopenid_distrusted, NULL, OR_AUTHCFG,
		  "AuthOpenIDDistrusted <a blacklist list of identity providers>"),
  AP_INIT_TAKE1("AuthOpenIDServerName", (CMD_HAND_TYPE) set_modauthopenid_server_name, NULL, OR_AUTHCFG,
		"AuthOpenIDServerName <server name and port prefix>"),
  AP_INIT_TAKE1("AuthOpenIDUserProgram", (CMD_HAND_TYPE) set_modauthopenid_auth_program, NULL, OR_AUTHCFG,
		"AuthOpenIDUserProgram <full path to authentication program>"),
  AP_INIT_TAKE23("AuthOpenIDAXAdd", (CMD_HAND_TYPE) set_modauthopenid_attribute_exchange_add, NULL, OR_AUTHCFG,
		 "AuthOpenIDAXAdd <alias> <uri> <required(default=true)>"),
  AP_INIT_ITERATE("AddAuthOpenIDMemcached", (CMD_HAND_TYPE) add_modauthopenid_memcached, NULL, RSRC_CONF,
		  "AddAuthOpenIDMemcached <a list of memcached host:port addresses>"),
  {NULL}
};


// Get the full URI of the request_rec's request location 
// clean_params specifies whether or not all openid.* and modauthopenid.* params should be cleared
static void full_uri(request_rec *r, std::string& result, modauthopenid_config *s_cfg, bool clean_params=false) {
  std::string uri(r->uri);

  std::string args;
  if(clean_params) {
    opkele::params_t params;
    if(r->args != NULL) params = modauthopenid::parse_query_string(std::string(r->args));
    modauthopenid::remove_openid_vars(params);
    args = params.append_query("", "");
  } else {
    args = (r->args == NULL) ? "" : "?" + std::string(r->args);
  }

  if(s_cfg->server_name == NULL) {
    const char* fwd_hostname = apr_table_get(r->headers_in, "X-Forwarded-Server");
    std::string hostname(fwd_hostname != NULL? fwd_hostname : r->hostname);

    const char* fwd_https = apr_table_get(r->headers_in, "X-Forwarded-HTTPS");
    std::string prefix = ((using_https != NULL && using_https(r->connection)) || (fwd_https != NULL && !strcmp(fwd_https, "on")))? "https://" : "http://";

    const char* fwd_port = apr_table_get(r->headers_in, "X-Forwarded-Port");
    apr_port_t i_port = fwd_port != NULL? atoi(fwd_port) : ap_get_server_port(r);
    char *port = apr_psprintf(r->pool, "%lu", (unsigned long) i_port);
    std::string s_port = (i_port == 80 || i_port == 443) ? "" : ":" + std::string(port);

    result = prefix + hostname + s_port + uri + args;
  }
  else
    result = std::string(s_cfg->server_name) + uri + args;
}

static int show_input(request_rec *r, modauthopenid_config *s_cfg, modauthopenid::error_result_t e) {
  if(s_cfg->login_page == NULL) {
    std::string msg = modauthopenid::error_to_string(e, false);
    return modauthopenid::show_html_input(r, msg);
  }
  opkele::params_t params;
  if(r->args != NULL) 
    params = modauthopenid::parse_query_string(std::string(r->args));
  modauthopenid::remove_openid_vars(params);  

  std::string uri_location;
  full_uri(r, uri_location, s_cfg, true);
  params["openauth_referrer"] = uri_location;

  params["modauthopenid.error"] = modauthopenid::error_to_string(e, true);
  return modauthopenid::http_redirect(r, params.append_query(s_cfg->login_page, ""));
}

static int show_input(request_rec *r, modauthopenid_config *s_cfg) {
  if(s_cfg->login_page == NULL) 
    return modauthopenid::show_html_input(r, "");
  opkele::params_t params;
  if(r->args != NULL) 
    params = modauthopenid::parse_query_string(std::string(r->args));
  modauthopenid::remove_openid_vars(params);
  std::string uri_location;
  full_uri(r, uri_location, s_cfg, true);
  params["openauth_referrer"] = uri_location;
  return modauthopenid::http_redirect(r, params.append_query(s_cfg->login_page, ""));
}

static bool is_trusted_provider(modauthopenid_config *s_cfg, std::string url) {
  if(apr_is_empty_array(s_cfg->trusted))
    return true;
  char **trusted_sites = (char **) s_cfg->trusted->elts;
  std::string base_url = modauthopenid::get_queryless_url(url);
  for (int i = 0; i < s_cfg->trusted->nelts; i++) {
    if(modauthopenid::regex_match(base_url, trusted_sites[i])) {
      modauthopenid::debug(base_url + " is a trusted identity provider");
      return true;
    }
  }
  modauthopenid::debug(base_url + " is NOT a trusted identity provider");
  return false;
}

static bool is_distrusted_provider(modauthopenid_config *s_cfg, std::string url) {
  if(apr_is_empty_array(s_cfg->distrusted))
    return false;
  char **distrusted_sites = (char **) s_cfg->distrusted->elts;
  std::string base_url = modauthopenid::get_queryless_url(url);
  for (int i = 0; i < s_cfg->distrusted->nelts; i++) {
    if(modauthopenid::regex_match(base_url, distrusted_sites[i])) {
      modauthopenid::debug(base_url + " is a distrusted (on black list) identity provider");
      return true;
    }
  }
  modauthopenid::debug(base_url + " is NOT a distrusted identity provider (not blacklisted)");
  return false;
};

static const std::string realm(const std::string& identity, request_rec* r) {
    // Convert an identity URI from a hostname realm
    apr_uri_t uri;
    apr_uri_parse(r->pool, identity.c_str(), &uri);
    const std::string host(uri.hostname);
    const size_t d1 = host.find_last_of('.');
    if (d1 == std::string::npos)
        return host;
    size_t d2 = host.find_last_of('.', d1 - 1);
    if (d2 == std::string::npos)
        return host;
    return host.substr(d2 + 1);
}

static bool has_valid_session(request_rec *r, modauthopenid_config *s_cfg, modauthopenid_server_config* s_scfg, std::string& session_id) {
  // test for valid session - if so, return DECLINED
  if(session_id != "" && s_cfg->use_cookie) {
    modauthopenid::debug("found session_id in cookie: " + session_id);
    modauthopenid::session_t session;
    modauthopenid::SessionManager sm(s_scfg->memcached);
    sm.get_session(session_id, session);

    // if session found 
    if(std::string(session.identity) != "") {
      std::string uri_path;
      modauthopenid::base_dir(std::string(r->uri), uri_path);
      std::string valid_path(session.path);
      // if found session has a valid path
      const char* fwd_hostname = apr_table_get(r->headers_in, "X-Forwarded-Server");
      if(valid_path == uri_path.substr(0, valid_path.size()) && apr_strnatcmp(session.hostname.c_str(), fwd_hostname != NULL? fwd_hostname : r->hostname)==0) {

	    // set the session-env_vars
        std::string remote_user;
	    for(std::map<std::string,std::string>::const_iterator it = session.env_vars.begin(); it != session.env_vars.end(); ++it) {
	      std::string key = it->first;
	      std::string val = it->second;
          modauthopenid::debug("setting " + key + " to \"" + val + "\"");
          if (key == "REMOTE_USER")
            remote_user = val;
          else
	        apr_table_set(r->subprocess_env, apr_pstrdup(r->pool, key.c_str()), apr_pstrdup(r->pool, val.c_str()));
	    }

        if (!remote_user.empty())
	      r->user = apr_pstrdup(r->pool, std::string(remote_user).c_str());
        else
	      r->user = apr_pstrdup(r->pool, std::string(session.identity).c_str());
	    modauthopenid::debug("setting REMOTE_USER to \"" + std::string(r->user) + "\"");

        // Store the identity in an env var
        apr_table_set(r->subprocess_env, apr_pstrdup(r->pool, "REALM"), apr_pstrdup(r->pool, realm(session.identity, r).c_str()));
	    return true;

      } else {
	    modauthopenid::debug("session found for different path or hostname");
      }
    }
  }
  return false;
};


static int start_authentication_session(request_rec *r, modauthopenid_config *s_cfg, modauthopenid_server_config* s_scfg, opkele::params_t& params, 
					std::string& return_to, std::string& trust_root) {
  // remove all openid GET query params (openid.*) - we don't want that maintained through
  // the redirection process.  We do, however, want to keep all other GET params.
  // also, add a nonce for security 
  std::string identity = params.get_param("openid_identifier");
  modauthopenid::remove_openid_vars(params);

  // add a nonce and reset what return_to is
  std::string nonce, re_direct;
  modauthopenid::make_rstring(10, nonce);
  modauthopenid::MoidConsumer consumer(s_scfg->memcached, nonce, return_to);    
  params["modauthopenid.nonce"] = nonce;
  full_uri(r, return_to, s_cfg);
  return_to = params.append_query(return_to, "");

  // get identity provider and redirect
  try {
    consumer.initiate(identity);
    opkele::openid_message_t cm; 

    opkele::ax_t ax;
    for(modauthopenid_ax_map::const_iterator it = (*s_cfg->attr).begin(); it != (*s_cfg->attr).end(); ++it) {
      const modauthopenid_ax_t attr = it->second;
      ax.add_attribute(attr.uri.c_str(), attr.required, NULL, attr.count);
    }

    re_direct = consumer.checkid_(cm, opkele::mode_checkid_setup, return_to, trust_root, &ax).append_query(consumer.get_endpoint().uri);
  } catch (opkele::failed_xri_resolution &e) {
    return show_input(r, s_cfg, modauthopenid::invalid_id);
  } catch (opkele::failed_discovery &e) {
    return show_input(r, s_cfg, modauthopenid::invalid_id);
  } catch (opkele::bad_input &e) {
    return show_input(r, s_cfg, modauthopenid::invalid_id);
  } catch (opkele::exception &e) {
    modauthopenid::debug("Error while fetching idP location: " + std::string(e.what()));
    return show_input(r, s_cfg, modauthopenid::no_idp_found);
  }
  if(!is_trusted_provider(s_cfg , re_direct) || is_distrusted_provider(s_cfg, re_direct))
    return show_input(r, s_cfg, modauthopenid::idp_not_trusted);
  return modauthopenid::http_redirect(r, re_direct);
};


static int set_session_cookie(request_rec *r, modauthopenid_config *s_cfg, modauthopenid_server_config* s_scfg, opkele::params_t& params, std::string identity, std::map<std::string,std::string>& env_vars) {
  // now set auth cookie, if we're doing session based auth
  std::string session_id, hostname, path, cookie_value, redirect_location, args;
  if(s_cfg->cookie_path != NULL) 
    path = std::string(s_cfg->cookie_path); 
  else 
    modauthopenid::base_dir(std::string(r->uri), path); 
  modauthopenid::make_rstring(32, session_id);
  session_id = std::string("OpenID_") + session_id;
  const char* fwd_hostname = apr_table_get(r->headers_in, "X-Forwarded-Server");
  hostname = std::string(fwd_hostname != NULL? fwd_hostname : r->hostname);
  modauthopenid::make_cookie_value(cookie_value, std::string(s_cfg->cookie_name), session_id, hostname, path, s_cfg->cookie_lifespan, s_cfg->secure_cookie); 
  modauthopenid::debug("setting cookie: " + cookie_value);
  apr_table_set(r->err_headers_out, "Set-Cookie", cookie_value.c_str());


  // save session values
  modauthopenid::session_t session;
  session.session_id = session_id;
  session.hostname = hostname;
  session.path = path;
  session.identity = identity;
  session.env_vars = env_vars;
  // lifespan will be 0 if not specified by user in config - so lasts as long as browser is open.  In this case, make it last for up to a day.
  // See issue 16 - http://trac.butterfat.net/public/mod_auth_openid/ticket/16
  time_t rawtime;
  time (&rawtime);
  if(s_cfg->cookie_lifespan == 0)
    session.expires_on = rawtime + 86400;
  else
    session.expires_on = rawtime + s_cfg->cookie_lifespan;

  modauthopenid::SessionManager sm(s_scfg->memcached);
  sm.store_session(session);

  modauthopenid::remove_openid_vars(params);
  args = params.append_query("", "").substr(1);
  if(args.length() == 0)
    r->args = NULL;
  else
    apr_cpystrn(r->args, args.c_str(), 1024);
  full_uri(r, redirect_location, s_cfg);
  return modauthopenid::http_redirect(r, redirect_location);
};

static int validate_authentication_session(request_rec *r, modauthopenid_config *s_cfg, modauthopenid_server_config* s_scfg, opkele::params_t& params, std::string& return_to) {
  // make sure nonce is present
  if(!params.has_param("modauthopenid.nonce")) 
    return show_input(r, s_cfg, modauthopenid::invalid_nonce);

  modauthopenid::MoidConsumer consumer(s_scfg->memcached, params.get_param("modauthopenid.nonce"), return_to);
  try {
    opkele::ax_t ax;
    opkele::params_t openidparams;
    modauthopenid::get_openid_params(openidparams, params);
    consumer.id_res(openidparams, &ax);
    
    // if no exception raised, check nonce
    if(!consumer.session_exists()) {
      return show_input(r, s_cfg, modauthopenid::invalid_nonce); 
    }

    // if we should be using a user specified auth program, run it to see if user is authorized
    if(s_cfg->use_auth_program && !modauthopenid::exec_auth(std::string(s_cfg->auth_program), consumer.get_claimed_id())) {
      return show_input(r, s_cfg, modauthopenid::unauthorized);       
    }

    // Make sure that identity is set to the original one given by the user (in case of delegation
    // this will be different than openid_identifier GET param
    std::string identity = consumer.get_claimed_id();
    consumer.kill_session();

    // Read out all requested ax-attributes and prepare them for storage in env_vars
    std::string remote_user;
    std::map<std::string, std::string> env_vars;
    env_vars["OPENID_IDENTITY"] = identity;
    for(modauthopenid_ax_map::const_iterator it = (*s_cfg->attr).begin(); it != (*s_cfg->attr).end(); ++it) {
      const modauthopenid_ax_t attr = it->second;
      std::string key = it->first;
      std::string val = ax.get_attribute(attr.uri.c_str());
      if (!val.empty()) {
        env_vars[key] = val;
        if (key == "REMOTE_USER")
          remote_user = val;
      }
    }

    // if we're not setting cookie - don't redirect, just show page
    if(s_cfg->use_cookie) 
      return set_session_cookie(r, s_cfg, s_scfg, params, identity, env_vars);
      
    if (!remote_user.empty())
      r->user = apr_pstrdup(r->pool, remote_user.c_str());
    else
      r->user = apr_pstrdup(r->pool, identity.c_str());
    modauthopenid::debug("setting REMOTE_USER to \"" + std::string(r->user) + "\"");

    // set the session-env_vars
    for(std::map<std::string,std::string>::const_iterator it = env_vars.begin(); it != env_vars.end(); ++it) {
      std::string key = it->first;
      std::string val = it->second;
      if (key != "REMOTE_USER")
        apr_table_set(r->subprocess_env, apr_pstrdup(r->pool, key.c_str()), apr_pstrdup(r->pool, val.c_str()));
    }

    // Store the identity in an env var
    apr_table_set(r->subprocess_env, apr_pstrdup(r->pool, "REALM"), apr_pstrdup(r->pool, realm(identity, r).c_str()));
    return DECLINED;

  } catch(opkele::exception &e) {
    modauthopenid::debug("Error in authentication: " + std::string(e.what()));
    return show_input(r, s_cfg, modauthopenid::unspecified);
  }
};

static int check_authn(request_rec *r) {
  modauthopenid_config *s_cfg = (modauthopenid_config *) ap_get_module_config(r->per_dir_config, &authopenid_module);
  if(!s_cfg->enabled)
    return DECLINED;
  const char* current_auth = ap_auth_type(r);
  if (!current_auth || strcasecmp(current_auth, "Open"))
    return DECLINED;

  modauthopenid_server_config *s_scfg;
  s_scfg = (modauthopenid_server_config *) ap_get_module_config(r->server->module_config, &authopenid_module);

  // make a record of our being called
  modauthopenid::debug("OpenID authentication for location \"" + std::string(r->uri) + "\"");

  // get the session id from the request cookie
  std::string session_id = "";
  modauthopenid::get_session_id(r, std::string(s_cfg->cookie_name), session_id);
  if(session_id != "" && s_cfg->use_cookie) {
      if (session_id.substr(0, 7) != "OpenID_")
          return DECLINED;
  }

  if(has_valid_session(r, s_cfg, s_scfg, session_id)) {
    r->ap_auth_type = const_cast<char*>(current_auth);
    return OK;
  }

  // parse the get/post params
  opkele::params_t params;
  modauthopenid::get_request_params(r, params);

  // get our current url and trust root
  std::string return_to, trust_root;
  full_uri(r, return_to, s_cfg);
  if(s_cfg->trust_root == NULL)
    modauthopenid::base_dir(return_to, trust_root);
  else
    trust_root = std::string(s_cfg->trust_root);

  // if user is posting id (only openid_identifier will contain a value)
  if(params.has_param("openid_identifier") && !params.has_param("openid.assoc_handle")) {
    r->ap_auth_type = const_cast<char*>(current_auth);
    return start_authentication_session(r, s_cfg, s_scfg, params, return_to, trust_root);

  } else if(params.has_param("openid.assoc_handle")) { // user has been redirected, authenticate them and set cookie
    r->ap_auth_type = const_cast<char*>(current_auth);
    return validate_authentication_session(r, s_cfg, s_scfg, params, return_to);

  } else { //display an input form
    r->ap_auth_type = const_cast<char*>(current_auth);
    if(params.has_param("openid.mode") && params.get_param("openid.mode") == "cancel")
      return show_input(r, s_cfg, modauthopenid::canceled);
    return show_input(r, s_cfg);
  }
}

static void mod_authopenid_register_hooks (apr_pool_t *p) {
  ap_hook_child_init(child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_check_authn(check_authn, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
}

//module AP_MODULE_DECLARE_DATA 
module AP_MODULE_DECLARE_DATA authopenid_module = {
	STANDARD20_MODULE_STUFF,
	create_modauthopenid_config,
	NULL, // config merge function - default is to override
	create_modauthopenid_server_config,
	NULL,
	mod_authopenid_cmds,
	mod_authopenid_register_hooks,
};
