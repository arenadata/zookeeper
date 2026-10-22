/**
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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.  See the License for the specific
 * language governing permissions and limitations under the License.
 */

package org.apache.zookeeper.server.jersey.cfg;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.apache.zookeeper.common.SecretUtils;
import org.apache.zookeeper.common.vault.MockVault;
import org.apache.zookeeper.common.vault.VaultCredentialProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class RestCfgVaultTest {

    private static final String DATA_PATH = "secret/data/zk/rest.ssl.jks.pass";

    @TempDir
    File tempDir;

    private MockVault vault;
    private File tokenFile;

    @BeforeEach
    public void startVault() throws IOException {
        vault = new MockVault();
        tokenFile = new File(tempDir, "vault-token");
        Files.write(tokenFile.toPath(), MockVault.TOKEN.getBytes(StandardCharsets.UTF_8));
    }

    @AfterEach
    public void stopVault() {
        vault.close();
        System.clearProperty(SecretUtils.CREDENTIAL_PROVIDER_PATH);
        System.clearProperty(VaultCredentialProvider.TOKEN_PATH);
        System.clearProperty(VaultCredentialProvider.RETRY_INTERVAL_MS);
        System.clearProperty(VaultCredentialProvider.RETRY_COUNT);
    }

    private void enableCredentialProvider() {
        System.setProperty(SecretUtils.CREDENTIAL_PROVIDER_PATH, vault.uri("secret/zk"));
        System.setProperty(VaultCredentialProvider.TOKEN_PATH, tokenFile.getAbsolutePath());
        System.setProperty(VaultCredentialProvider.RETRY_INTERVAL_MS, "1");
    }

    private RestCfg cfg(String properties) throws IOException {
        return new RestCfg(new ByteArrayInputStream(properties.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testFlatValueWithoutProvider() throws IOException {
        RestCfg cfg = cfg("rest.ssl.jks.pass = 123456\n");
        assertEquals("123456", cfg.getJKSPassword());
    }

    @Test
    public void testMissingKeyWithoutProvider() throws IOException {
        assertNull(cfg("rest.port = 9998\n").getJKSPassword());
    }

    @Test
    public void testVaultValueTakesPrecedenceOverFlatValue() throws IOException {
        vault.putSecret(DATA_PATH, "value", "vault-pass");
        enableCredentialProvider();
        RestCfg cfg = cfg("rest.ssl.jks.pass = 123456\n");
        assertEquals("vault-pass", cfg.getJKSPassword());
    }

    @Test
    public void testFlatValueWhenVaultHasNoAlias() throws IOException {
        enableCredentialProvider();
        RestCfg cfg = cfg("rest.ssl.jks.pass = 123456\n");
        assertEquals("123456", cfg.getJKSPassword());
    }

    @Test
    public void testFailsFastWhenVaultIsUnreadable() throws IOException {
        vault.revokeToken(MockVault.TOKEN);
        enableCredentialProvider();
        System.setProperty(VaultCredentialProvider.RETRY_COUNT, "0");
        RestCfg cfg = cfg("rest.ssl.jks.pass = 123456\n");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                cfg::getJKSPassword);
        assertTrue(e.getMessage().contains("rest.ssl.jks.pass"), e.getMessage());
    }
}
