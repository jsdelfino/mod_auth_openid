/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/* $Rev$ $Date$ */

#include "mod_auth_openid.h"

/**
 * Memcached access functions.
 */

#include "apr.h"
#include "apu.h"
#include "apr_general.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_memcache.h"
#include "apr_network_io.h"

#include <string>
#include <sstream>

namespace modauthopenid {
namespace memcache {

const apr_status_t MemCached::addServer(const std::string& host, const int port) {
  char sp[16];
  sprintf(sp, "%d", port);
  debug("memcache::addServer " + host + ":" + sp);
  apr_memcache_server_t *server;
  const apr_status_t sc = apr_memcache_server_create(pool, host.c_str(), (apr_port_t)port, 1, 1, 1, 600, &server);
  if (sc != APR_SUCCESS)
    return failure(sc, "Could not create memcached server");
  const apr_status_t as = apr_memcache_add_server(mc, server);
  if (as != APR_SUCCESS)
    return failure(as, "Could not add memcached server");
  return APR_SUCCESS;
}

const apr_status_t MemCached::addServers(const apr_array_header_t* addrs) {
  const char** servers = (const char**)addrs->elts;
  for (int i = 0; i < addrs->nelts; i++) {
    const std::string s(servers[i]);
    const size_t c = s.find(':');
    const std::string host = c == std::string::npos? s : s.substr(0, c);
    const int port = c == std::string::npos? 11211 : atoi(s.substr(c + 1).c_str());
    const apr_status_t rc = addServer(host, port);
    if (rc != APR_SUCCESS)
      return rc;
  }
  return APR_SUCCESS;
}

const apr_status_t failure(const apr_status_t rc, const std::string& msg) {
    debug(msg);
    return rc;
}

const char* nospaces(const char* s) {
    char* c = const_cast<char*>(s);
    for (; *c; c++)
        if (*c == ' ')
            *c = '\t';
    return s;
}

const apr_status_t post(const std::string& key, const std::string& val, const int timeout, const MemCached& cache) {
    debug("memcache::post::key " + key);
    debug("memcache::post::value " + val);

    const apr_status_t rc = apr_memcache_add(cache.mc, nospaces(key.c_str()), const_cast<char*>(val.c_str()), val.length(), timeout, 27);
    if (rc != APR_SUCCESS)
        return failure(rc, "Could not add memcached entry");
    return rc;
}

const apr_status_t put(const std::string& key, const std::string& val, const int timeout, const MemCached& cache) {
    debug("memcache::put::key " + key);
    debug("memcache::put::value " + val);

    const apr_status_t rc = apr_memcache_set(cache.mc, nospaces(key.c_str()), const_cast<char*>(val.c_str()), val.length(), timeout, 27);
    if (rc != APR_SUCCESS)
        return failure(rc, "Could not set memcached entry");
    return rc;
}

const string get(const std::string& key, const MemCached& cache) {
    debug("memcache::get::key " + key);

    char *data;
    apr_size_t size;
    const apr_status_t rc = apr_memcache_getp(cache.mc, cache.pool, nospaces(key.c_str()), &data, &size, NULL);
    if (rc != APR_SUCCESS) {
        debug("Could not get memcached entry");
        return std::string();
    }
    const std::string val(data, size);

    debug("memcache::get::result " + val);
    return val;
}

const apr_status_t del(const std::string& key, const MemCached& cache) {
    debug("memcache::delete::key " + key);

    const apr_status_t rc = apr_memcache_delete(cache.mc, nospaces(key.c_str()), 0);
    if (rc != APR_SUCCESS)
        return failure(rc, "Could not delete memcached entry");
    return APR_SUCCESS;
}

}
}

