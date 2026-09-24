/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper.common.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.net.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class VaultConnectionInfoTest {

    @Test
    public void testFullUri() throws Exception {
        VaultConnectionInfo info = new VaultConnectionInfo(
            URI.create("vault://https@bao.example.com:8201/secret/zookeeper/prod?key=password"));
        assertEquals("https://bao.example.com:8201", info.baseUrl());
        assertTrue(info.isHttps());
        assertEquals("bao.example.com", info.getHost());
        assertEquals("password", info.getField());
        assertEquals("secret/data/zookeeper/prod/ssl.keyStore.password", info.dataPath("ssl.keyStore.password"));
    }

    @Test
    public void testDefaults() throws Exception {
        VaultConnectionInfo info = new VaultConnectionInfo(URI.create("vault://bao.example.com/secret"));
        assertEquals("https://bao.example.com:8200", info.baseUrl());
        assertEquals("value", info.getField());
        assertEquals("secret/data/alias", info.dataPath("alias"));
    }

    @Test
    public void testHttp() throws Exception {
        VaultConnectionInfo info = new VaultConnectionInfo(URI.create("vault://HTTP@localhost:8200/kv/zk/"));
        assertEquals("http://localhost:8200", info.baseUrl());
        assertFalse(info.isHttps());
        assertEquals("kv/data/zk/a", info.dataPath("a"));
    }

    @Test
    public void testIpv6Host() throws Exception {
        VaultConnectionInfo info = new VaultConnectionInfo(URI.create("vault://https@[::1]:8200/secret"));
        assertEquals("https://[::1]:8200", info.baseUrl());
    }

    @Test
    public void testApiUrlEncodesSegments() throws Exception {
        VaultConnectionInfo info = new VaultConnectionInfo(URI.create("vault://localhost:8200/secret/zk"));
        assertEquals("https://localhost:8200/v1/secret/data/zk/a%20b%3Fc/d.e_f~g-h",
            info.apiUrl(info.dataPath("a b?c/d.e_f~g-h")));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://localhost:8200/secret",
        "vault://ftp@localhost:8200/secret",
        "vault:///secret",
        "vault://localhost:8200",
        "vault://localhost:8200/",
        "vault://localhost:8200/secret//zk",
        "vault://localhost:8200/secret/../zk",
    })
    public void testInvalidUri(String uri) {
        assertThrows(IOException.class, () -> new VaultConnectionInfo(URI.create(uri)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "a//b", "./a", "a/..", "a\nb"})
    public void testInvalidPath(String path) {
        assertThrows(IOException.class, () -> VaultConnectionInfo.checkPath(path));
    }
}
