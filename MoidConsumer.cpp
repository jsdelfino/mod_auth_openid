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
  using namespace std;
  using namespace opkele;
 
  MoidConsumer::MoidConsumer(const memcache::MemCached& memcached, const string& _asnonceid, const string& _serverurl) :
                             memcached(memcached), asnonceid(_asnonceid), serverurl(_serverurl), endpoint_set(false), normalized_id("") {
  }


  assoc_t MoidConsumer::store_assoc(const string& server,const string& handle,const string& type,const secret_t& secret,int expires_in) {
    debug("Storing association for \"" + server + "\" and handle \"" + handle + "\"");
    const int expires_on = expires_in + time(0);

    std::ostringstream k;
    k << "(openIDAssociation " << server << " " << handle << ")";
    std::ostringstream q;
    q << server << " " << handle << " " << util::encode_base64(&(secret.front()),secret.size()) << " " << expires_on << " " << type;
    const apr_status_t rc = memcache::put(k.str(), q.str(), expires_in, memcached);
    if (rc != APR_SUCCESS)
        memcache::failure(rc, "Could not store association");

    std::ostringstream k2;
    k2 << "(openIDAssociation " << server << ")";
    const apr_status_t rc2 = memcache::put(k2.str(), q.str(), expires_in, memcached);
    if (rc2 != APR_SUCCESS)
        memcache::failure(rc2, "Could not store association");

    return assoc_t(new association(server, handle, type, secret, expires_on, false));
  }

  assoc_t MoidConsumer::retrieve_assoc(const string& server, const string& handle) {
    debug("looking up association: server = " + server + " handle = " + handle);
    std::ostringstream k;
    k << "(openIDAssociation " << server;
    if (handle != "")
      k << " " << handle;
    k << ")";
    const std::string v = memcache::get(k.str(), memcached);
    if (v == "")
      throw failed_lookup(OPKELE_CP_ "Could not find association.");

    std::istringstream q(v);
    std::string qserver;
    std::string qhandle;
    std::string qsecret;
    int qexpires_on;
    std::string qtype;
    q >> qserver >> qhandle >> qsecret >> qexpires_on >> qtype;
    secret_t secret; 
    util::decode_base64(qsecret, secret);

    return assoc_t(new association(qserver, qhandle, qtype, secret, qexpires_on, false));
  }

  void MoidConsumer::invalidate_assoc(const string& server,const string& handle) {
    debug("invalidating association: server = " + server + " handle = " + handle);
    std::ostringstream k;
    k << "(openIDAssociation " << server << " " << handle << ")";
    const apr_status_t rc = memcache::del(k.str(), memcached);
    if (rc != APR_SUCCESS)
      memcache::failure(rc, "Could not invalidate assocation for server \"" + server + "\" and handle \"" + handle + "\"");
  }

  assoc_t MoidConsumer::find_assoc(const string& server) {
    debug("looking up association: server = " + server);
    return retrieve_assoc(server, "");
  }

  void MoidConsumer::check_nonce(const string& server, const string& nonce) {
    debug("checking nonce " + nonce);

    std::ostringstream k;
    k << "(openIDResponseNonces " << server << " " << nonce << ")";
    const std::string v = memcache::get(k.str(), memcached);
    if (v != "") {
      debug("found preexisting nonce - could be a replay attack");
      throw opkele::id_res_bad_nonce(OPKELE_CP_ "old nonce used again - possible replay attack");
    }

    // so, old nonce not found, insert it into nonces table.  Expiration time will be based on association
    const int expires_in = find_assoc(server)->expires_in();
    const int expires_on = expires_in + time(0);
    std::ostringstream q;
    q << server << " " << nonce << " " << expires_in;
    const apr_status_t rc = memcache::put(k.str(), q.str(), expires_in, memcached);
    if (rc != APR_SUCCESS)
      memcache::failure(rc, "Could not add new nonce to response_nonces");
  }

  bool MoidConsumer::session_exists() {
    std::ostringstream k;
    k << "(openIDAuthenticationSessions " << asnonceid << ")";
    const std::string v = memcache::get(k.str(), memcached);
    if (v == "") {
      debug("could not find authentication session \"" + asnonceid + "\" in db.");
      return false;
    }
    return true;
  }

  void MoidConsumer::begin_queueing() {
    endpoint_set = false;
    std::ostringstream k;
    k << "(openIDAuthenticationSessions " << asnonceid << ")";
    const apr_status_t rc = memcache::del(k.str(), memcached);
    if (rc != APR_SUCCESS)
        memcache::failure(rc, "Problem resetting authentication session");
  }

  void MoidConsumer::queue_endpoint(const openid_endpoint_t& ep) {
    if(!endpoint_set) {
      debug("Queueing endpoint " + ep.claimed_id + " : " + ep.local_id + " @ " + ep.uri);
      time_t now = time(0);
      int expires_on = now + 3600;  // allow nonce to exist for up to one hour without being returned

      std::ostringstream k;
      k << "(openIDAuthenticationSessions " << asnonceid << ")";
      std::ostringstream q;
      q << asnonceid << " " << ep.uri << " " << ep.claimed_id << " " << ep.local_id << " " << expires_on;
      const apr_status_t rc = memcache::put(k.str(), q.str(), 3600, memcached);
      if (rc != APR_SUCCESS) {
          memcache::failure(rc, "problem queuing endpoint");
        return;
      }
      endpoint_set = true;
    }
  }

  const openid_endpoint_t& MoidConsumer::get_endpoint() const {
    debug("Fetching endpoint");
    std::ostringstream k;
    k << "(openIDAuthenticationSessions " << asnonceid << ")";
    const std::string v = memcache::get(k.str(), memcached);
    if(v == "") {
      debug("Could not find an endpoint for authentication session \"" + asnonceid + "\" in db.");
      throw opkele::exception(OPKELE_CP_ "No more endpoints queued");
    } 

    std::istringstream q(v);
    std::string qnonce;
    q >> qnonce >> endpoint.uri >> endpoint.claimed_id >> endpoint.local_id;
    return endpoint;
  }

  void MoidConsumer::next_endpoint() {
    debug("Clearing all session information - we're only storing one endpoint, can't get next one, cause we didn't store it.");
    std::ostringstream k;
    k << "(openIDAuthenticationSessions " << asnonceid << ")";
    const apr_status_t rc = memcache::del(k.str(), memcached);
    if (rc != APR_SUCCESS)
        memcache::failure(rc, "Problem in next_endpoint()");
    endpoint_set = false;
  }

  void MoidConsumer::kill_session() {
    std::ostringstream k;
    k << "(openIDAuthenticationSessions " << asnonceid << ")";
    const apr_status_t rc = memcache::del(k.str(), memcached);
    if (rc != APR_SUCCESS)
        memcache::failure(rc, "Problem killing session");
  }

  void MoidConsumer::set_normalized_id(const string& nid) {
    debug("Set normalized id to: " + nid);
    normalized_id = nid;

    std::ostringstream k;
    k << "(openIDAuthenticationSessions " << asnonceid << ")";
    const std::string v = memcache::get(k.str(), memcached);
    if (v == "") {
      debug("could not find an normalized_id for authentication session \"" + asnonceid + "\" in db.");
      throw opkele::exception(OPKELE_CP_ "cannot get normalized id");
    }
    std::istringstream q(v);
    std::string qnonce;
    openid_endpoint_t qep;
    int qexpires_on;
    q >> qnonce >> qep.uri >> qep.claimed_id >> qep.local_id >> qexpires_on;

    std::ostringstream u;
    u << qnonce << " " << qep.uri << " " << qep.claimed_id << " " << qep.local_id << " " << qexpires_on << " " << normalized_id;
    const time_t now = time(0);
    const int expires_in = qexpires_on <= now ? 1 : qexpires_on - now;
    apr_status_t rc = memcache::put(k.str(), u.str(), expires_in, memcached);
    if (rc != APR_SUCCESS)
      memcache::failure(rc, "problem settting normalized id");
  }

  const string MoidConsumer::get_normalized_id() const {
    if(normalized_id != "") {
      debug("getting normalized id - " + normalized_id);
      return normalized_id;
    }
    std::ostringstream k;
    k << "(openIDAuthenticationSessions " << asnonceid << ")";
    const std::string v = memcache::get(k.str(), memcached);
    if (v == "") {
      debug("could not find an normalized_id for authentication session \"" + asnonceid + "\" in db.");
      throw opkele::exception(OPKELE_CP_ "cannot get normalized id");
    }
    std::istringstream q(v);
    std::string qnonce;
    openid_endpoint_t qep;
    int qexpires_on;
    q >> qnonce >> qep.uri >> qep.claimed_id >> qep.local_id >> qexpires_on >> normalized_id;
    return normalized_id;
  }

  const string MoidConsumer::get_this_url() const {
    return serverurl;
  }

}



