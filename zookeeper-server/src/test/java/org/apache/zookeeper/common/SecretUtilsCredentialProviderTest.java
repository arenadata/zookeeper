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

package org.apache.zookeeper.common;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Security;
import org.apache.zookeeper.common.vault.MockVault;
import org.apache.zookeeper.common.vault.VaultCredentialProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class SecretUtilsCredentialProviderTest {

    private static final String PASSWORD = "zookeeper.ssl.keyStore.password";
    private static final String PASSWORD_PATH = "zookeeper.ssl.keyStore.passwordPath";

    @TempDir
    File tempDir;

    private MockVault vault;
    private ZKConfig config;

    @BeforeAll
    public static void addBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterAll
    public static void removeBouncyCastle() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @BeforeEach
    public void setUp() throws IOException {
        vault = new MockVault();
        File tokenFile = new File(tempDir, "vault-token");
        Files.write(tokenFile.toPath(), MockVault.TOKEN.getBytes(StandardCharsets.UTF_8));
        config = new ZKConfig();
        config.setProperty(SecretUtils.CREDENTIAL_PROVIDER_PATH, vault.uri("secret/zookeeper"));
        config.setProperty(VaultCredentialProvider.TOKEN_PATH, tokenFile.getAbsolutePath());
        config.setProperty(VaultCredentialProvider.RETRY_INTERVAL_MS, "1");
    }

    @AfterEach
    public void tearDown() {
        vault.close();
    }

    @Test
    public void testAliasIsTheZooCfgKey() {
        assertEquals("ssl.keyStore.password", SecretUtils.aliasOf(PASSWORD));
        assertEquals("metricsProvider.ssl.keyStore.password", SecretUtils.aliasOf("metricsProvider.ssl.keyStore.password"));
    }

    @Test
    public void testNoProvider() throws IOException {
        ZKConfig empty = new ZKConfig();
        assertFalse(SecretUtils.hasCredentialProvider(empty));
        assertNull(SecretUtils.getCredential(empty, "ssl.keyStore.password"));
        assertTrue(SecretUtils.hasCredentialProvider(config));
    }

    @Test
    public void testUnsupportedScheme() {
        config.setProperty(SecretUtils.CREDENTIAL_PROVIDER_PATH, "jceks://file/etc/zookeeper/creds.jceks");
        IOException e = assertThrows(IOException.class, () -> SecretUtils.getCredential(config, "a"));
        assertThat(e.getMessage(), containsString("only vault://"));
    }

    @Test
    public void testPasswordPrecedence() throws IOException {
        config.setProperty(PASSWORD, "from-config");
        assertEquals("from-config", SecretUtils.getPassword(config, PASSWORD, PASSWORD_PATH));

        File passwordFile = new File(tempDir, "password");
        Files.write(passwordFile.toPath(), "from-file".getBytes(StandardCharsets.UTF_8));
        config.setProperty(PASSWORD_PATH, passwordFile.getAbsolutePath());
        assertEquals("from-file", SecretUtils.getPassword(config, PASSWORD, PASSWORD_PATH));

        vault.putSecret("secret/data/zookeeper/ssl.keyStore.password", "value", "from-vault");
        assertEquals("from-vault", SecretUtils.getPassword(config, PASSWORD, PASSWORD_PATH));
    }

    @Test
    public void testPasswordWhenProviderFails() {
        vault.revokeToken(MockVault.TOKEN);
        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> SecretUtils.getPassword(config, PASSWORD, PASSWORD_PATH));
        assertThat(e.getMessage(), containsString("ssl.keyStore.password"));
    }

    @Test
    public void testSslContextWithStorePasswordsInVault() throws Exception {
        X509TestContext context = X509TestContext.newBuilder()
            .setTempDir(tempDir)
            .setKeyStoreKeyType(X509KeyType.EC)
            .setTrustStoreKeyType(X509KeyType.EC)
            .setKeyStorePassword("keystore-pass")
            .setTrustStorePassword("truststore-pass")
            .build();
        try (ClientX509Util x509Util = new ClientX509Util()) {
            config.setProperty(x509Util.getSslKeystoreLocationProperty(),
                context.getKeyStoreFile(KeyStoreFileType.JKS).getAbsolutePath());
            config.setProperty(x509Util.getSslTruststoreLocationProperty(),
                context.getTrustStoreFile(KeyStoreFileType.JKS).getAbsolutePath());
            assertThrows(X509Exception.SSLContextException.class, () -> x509Util.createSSLContextAndOptions(config));

            vault.putSecret("secret/data/zookeeper/ssl.keyStore.password", "value", "keystore-pass");
            vault.putSecret("secret/data/zookeeper/ssl.trustStore.password", "value", "truststore-pass");
            assertNotNull(x509Util.createSSLContextAndOptions(config).getSSLContext());
        }
    }
}
