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

/**
 * Modified to use Memcached instead of Sqlite.
 */

namespace modauthopenid {

  SessionManager::SessionManager(const memcache::MemCached& memcached) : memcached(memcached) {
  }

  void SessionManager::get_session(const std::string& session_id, session_t& session) {
    std::ostringstream k1;
    k1 << "session/" << session_id;
    const std::string v1 = memcache::get(k1.str(), memcached);
    if (v1 == "")
        return;
    std::istringstream q1(v1);
    q1 >> session.session_id >> session.hostname >> session.path >> session.identity >> session.expires_on;

    std::ostringstream k2;
    k2 << "env_vars/" << session.session_id;
    const std::string v2 = memcache::get(k2.str(), memcached);
    if (v2 == "")
        return;
    std::istringstream q2(v2);
    for(;;) {
      std::string key;
      q2 >> key;
      if (key == "")
          break;
      std::string val;
      q2 >> val;
      session.env_vars[key] = string(val);
    }
  }

  void SessionManager::store_session(const session_t& session) {
    const time_t now = time(0);
    const int timeout = now >= session.expires_on? 1 : session.expires_on - now;

    std::ostringstream k1;
    k1 << "session/" << session.session_id;
    std::ostringstream q1;
    q1 << session.session_id << " " << session.hostname << " " << session.path << " " << session.identity << " " << session.expires_on;
    const apr_status_t rc = memcache::put(k1.str(), q1.str(), timeout, memcached);
    if (rc != APR_SUCCESS) {
        memcache::failure(rc, "Could not store session");
        return;
    }

    std::ostringstream k2;
    k2 << "env_vars/" << session.session_id;
    std::ostringstream q2;
    for(map<string,string>::const_iterator it = session.env_vars.begin(); it != session.env_vars.end(); ++it) {
      const std::string key = it->first;
      const std::string val = it->second;
      q2 << key << " " << val;
    }
    const apr_status_t rc2 = memcache::put(k2.str(), q2.str(), timeout, memcached);
    if (rc2 != APR_SUCCESS)
        memcache::failure(rc2, "Could not store env vars");
  }

}
