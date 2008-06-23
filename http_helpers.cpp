/*
Copyright (C) 2007 Butterfat, LLC (http://butterfat.net)

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

namespace modauthopenid {
  using namespace std;

  int http_sendstring(request_rec *r, std::string s) {
    // no idea why the following line only sometimes worked.....                                                                                                //apr_table_setn(r->headers_out, "Content-Type", "text/html");
    ap_set_content_type(r, "text/html");
    const char *c_s = s.c_str();
    conn_rec *c = r->connection;
    apr_bucket *b;
    apr_bucket_brigade *bb = apr_brigade_create(r->pool, c->bucket_alloc);
    b = apr_bucket_transient_create(c_s, strlen(c_s), c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS)
      return HTTP_INTERNAL_SERVER_ERROR;
    return OK;
  };

  int http_redirect(request_rec *r, std::string location) {
    apr_table_set(r->headers_out, "Location", location.c_str());
    apr_table_setn(r->headers_out, "Cache-Control", "no-cache");
    debug("redirecting client to: " + location);
    return HTTP_MOVED_TEMPORARILY;
  };

  int show_html_input(request_rec *r, std::string msg) {
    opkele::params_t params;
    if(r->args != NULL)
      params = parse_query_string(std::string(r->args));
    std::string identity = params.has_param("openid_identifier") ? params.get_param("openid_identifier") : "";
    remove_openid_vars(params);
    std::map<std::string,std::string>::iterator iter;
    std::string args = "";
    std::string key, value;
    for(iter = params.begin(); iter != params.end(); iter++) {
      key = html_escape(iter->first);
      value = html_escape(iter->second);
      args += "<input type=\"hidden\" name=\"" + key + "\" value = \"" + value + "\" />";
    }
    std::string result =
    "<html><head><title>Protected Location</title><style type=\"text/css\">"
    "#msg { border: 1px solid #ff0000; background: #ffaaaa; font-weight: bold; padding: 5px; }\n"
    "a { text-decoration: none; }\n"
    "a:hover { text-decoration: underline; }\n"
    "#desc { border: 1px solid #000; background: #ccc; padding: 10px; }\n"
    "#sig { text-align: center; font-style: italic; margin-top: 50px; word-spacing: .3em; color: #777; }\n"
    ".loginbox { background: url(http://www.openid.net/login-bg.gif) no-repeat; background-color: #fff; " // logo location is in 1.1 spec, should stay same
    " background-position: 0 50%; color: #000; padding-left: 18px; }\n"
    "form { margin: 15px; }\n"
    "</style></head><body>"
    "<h1>Protected Location</h1>"
    "<p id=\"desc\">This site is protected and requires that you identify yourself with an "
    "<a href=\"http://openid.net\">OpenID</a> url.  To find out how it works, see "
    "<a href=\"http://openid.net/what/\">http://openid.net/what/</a>.  You can sign up for "
    "an identity on one of the sites listed <a href=\"http://openid.net/get/\">here</a>.</p>"
      + (msg.empty()?"":"<div id=\"msg\">"+msg+"</div>") +
    "<form action=\"\" method=\"get\">"
    "<b>Identity URL:</b> <input type=\"text\" name=\"openid_identifier\" value=\""+identity+"\" size=\"30\" class=\"loginbox\" />"
    "<input type=\"submit\" value=\"Log In\" />" + args +
    "</form>"
    "<div id=\"sig\"><a href=\"" + PACKAGE_URL + "\">" + PACKAGE_STRING + "</a></div>"
      "<body></html>";
    return http_sendstring(r, result);
  };

  void get_session_id(request_rec *r, std::string cookie_name, std::string& session_id) {
    const char * cookies_c = apr_table_get(r->headers_in, "Cookie");
    if(cookies_c == NULL)
      return;
    std::string cookies(cookies_c);
    std::vector<std::string> pairs = explode(cookies, ";");
    for(std::string::size_type i = 0; i < pairs.size(); i++) {
      std::vector<std::string> pair = explode(pairs[i], "=");
      if(pair.size() == 2) {
	std::string key = pair[0];
	strip(key);
	std::string value = pair[1];
	strip(value);
	debug("cookie sent by client: \""+key+"\"=\""+value+"\"");
	if(key == cookie_name) {
	  session_id = pair[1];
	  return;
	}
      }
    }
  };

  // get the base directory of the url
  void base_dir(string path, string& s) {
    // guaranteed that path will at least be "/" - but just to be safe... 
    if(path.size() == 0)
      return;
    string::size_type q = path.find('?', 0);
    int i;
    if(q != string::npos)
      i = path.find_last_of('/', q);
    else
      i = path.find_last_of('/');
    s = path.substr(0, i+1);
  };

}
