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

#ifndef memcache_h
#define memcache_h

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

/**
 * Report a failure.
 */
const apr_status_t failure(const apr_status_t rc, const std::string& msg);

/**
 * Represents a memcached context.
 */
class MemCached {
public:
    MemCached() : owner(false), pool(NULL) {
    }

    MemCached(const string host, const int port, apr_pool_t* pool) : owner(true), pool(pool) {
        apr_pool_create(&pool, NULL);
        apr_memcache_create(pool, 1, 0, &mc);
        addServer(host, port);
    }

    MemCached(const apr_array_header_t* addrs, apr_pool_t* pool) : owner(true), pool(pool) {
        apr_pool_create(&pool, NULL);
        apr_memcache_create(pool, addrs->nelts, 0, &mc);
        addServers(addrs);
    }

    MemCached(const MemCached& c) : owner(false), pool(c.pool), mc(c.mc) {
    }

    ~MemCached() {
        if (!owner)
            return;
    }

private:
    bool owner;
    apr_pool_t* pool;
    apr_memcache_t* mc;

    friend const apr_status_t post(const std::string& key, const std::string& val, const int timeout, const MemCached& cache);
    friend const apr_status_t put(const std::string& key, const std::string& val, const int timeout, const MemCached& cache);
    friend const std::string get(const std::string& key, const MemCached& cache);
    friend const apr_status_t del(const std::string& key, const MemCached& cache);

    const apr_status_t addServer(const std::string& host, const int port);
    const apr_status_t addServers(const apr_array_header_t* addrs);
};

/**
 * Replace spaces by tabs (as spaces are not allowed in memcached keys).
 */
const char* nospaces(const char* s);

/**
 * Post a new item to the cache.
 */
const apr_status_t post(const std::string& key, const std::string& val, const int timeout, const MemCached& cache);

/**
 * Update an item in the cache. If the item doesn't exist it is added.
 */
const apr_status_t put(const std::string& key, const std::string& val, const int timeout, const MemCached& cache);

/**
 * Get an item from the cache.
 */
const string get(const std::string& key, const MemCached& cache);

/**
 * Delete an item from the cache
 */
const apr_status_t del(const std::string& key, const MemCached& cache);

}
}

#endif /* memcache_h */
