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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import org.apache.zookeeper.common.KeyStoreFileType;
import org.apache.zookeeper.common.X509TestContext;
import org.apache.zookeeper.common.X509Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class VaultTrustStoreTest {

    private static final String ALIAS = "ssl.keyStore.password";
    private static final String STORE_PASSWORD = "changeit";

    @TempDir
    File tempDir;

    private X509TestContext x509;
    private MockVault vault;
    private Map<String, String> settings;

    @BeforeAll
    public static void addBouncyCastle() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterAll
    public static void removeBouncyCastle() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @BeforeEach
    public void setUp() throws Exception {
        x509 = X509TestContext.newBuilder().setTempDir(tempDir).setKeyStorePassword(STORE_PASSWORD).build();
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(new KeyManager[] {X509Util.createKeyManager(
            x509.getKeyStoreFile(KeyStoreFileType.JKS).getAbsolutePath(), STORE_PASSWORD, null)}, null, null);
        vault = new MockVault(serverContext);
        vault.putSecret("secret/data/zookeeper/" + ALIAS, "value", "s3cret");
        File tokenFile = new File(tempDir, "vault-token");
        Files.write(tokenFile.toPath(), MockVault.TOKEN.getBytes(StandardCharsets.UTF_8));
        settings = new HashMap<>();
        settings.put(VaultCredentialProvider.TOKEN_PATH, tokenFile.getAbsolutePath());
        settings.put(VaultCredentialProvider.RETRY_COUNT, "0");
    }

    @AfterEach
    public void tearDown() {
        vault.close();
        VaultCredentialProvider.clearProviders();
    }

    private VaultCredentialProvider provider() throws IOException {
        return VaultCredentialProvider.get(URI.create(vault.uri("secret/zookeeper")), settings::get);
    }

    private void useTrustStore(File file) {
        settings.put(VaultCredentialProvider.TRUSTSTORE_LOCATION, file.getAbsolutePath());
    }

    /**
     * Writes the CA that signed the Vault certificate to a password-protected store.
     */
    private File writeTrustStore(String type, String extension) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(type);
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", x509.getTrustStoreCertificates().get(0));
        File file = new File(tempDir, "vault-truststore" + extension);
        try (OutputStream out = Files.newOutputStream(file.toPath())) {
            trustStore.store(out, STORE_PASSWORD.toCharArray());
        }
        return file;
    }

    @Test
    public void testPemTrustStore() throws Exception {
        useTrustStore(x509.getTrustStoreFile(KeyStoreFileType.PEM));
        assertArrayEquals("s3cret".toCharArray(), provider().getCredential(ALIAS));
    }

    @Test
    public void testJksTrustStoreWithoutPassword() throws Exception {
        useTrustStore(writeTrustStore("JKS", ".jks"));
        assertArrayEquals("s3cret".toCharArray(), provider().getCredential(ALIAS));
    }

    @Test
    public void testJksTrustStoreWithWrongPassword() throws Exception {
        useTrustStore(writeTrustStore("JKS", ".jks"));
        settings.put(VaultCredentialProvider.TRUSTSTORE_PASSWORD, "wrong-password");
        IOException e = assertThrows(IOException.class, this::provider);
        assertThat(e.getMessage(), containsString("password was incorrect"));
    }

    @Test
    public void testPkcs12TrustStoreNeedsItsPassword() throws Exception {
        useTrustStore(writeTrustStore("PKCS12", ".p12"));
        IOException e = assertThrows(IOException.class, this::provider);
        assertThat(e.getMessage(), containsString("password was incorrect"));

        settings.put(VaultCredentialProvider.TRUSTSTORE_PASSWORD, STORE_PASSWORD);
        assertArrayEquals("s3cret".toCharArray(), provider().getCredential(ALIAS));
    }

    @Test
    public void testPkcs12TrustStoreNamedJks() throws Exception {
        File trustStore = writeTrustStore("PKCS12", ".jks");
        useTrustStore(trustStore);
        IOException e = assertThrows(IOException.class, this::provider);
        assertThat(e.getMessage(), containsString(trustStore.getAbsolutePath()
            + ": no certificate readable without a password"));

        settings.put(VaultCredentialProvider.TRUSTSTORE_PASSWORD, STORE_PASSWORD);
        assertArrayEquals("s3cret".toCharArray(), provider().getCredential(ALIAS));
    }

    @Test
    public void testServerOutsideTrustStore() {
        assertThrows(SSLHandshakeException.class, () -> provider().getCredential(ALIAS));
    }
}
