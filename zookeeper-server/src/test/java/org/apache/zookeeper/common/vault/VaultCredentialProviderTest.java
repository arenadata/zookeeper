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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class VaultCredentialProviderTest {

    private static final String ALIAS = "ssl.keyStore.password";
    private static final String DATA_PATH = "secret/data/zookeeper/" + ALIAS;

    @TempDir
    File tempDir;

    private MockVault vault;
    private File tokenFile;
    private Map<String, String> settings;

    @BeforeEach
    public void setUp() throws IOException {
        vault = new MockVault();
        tokenFile = new File(tempDir, "vault-token");
        writeToken(MockVault.TOKEN);
        settings = new HashMap<>();
        settings.put(VaultCredentialProvider.TOKEN_PATH, tokenFile.getAbsolutePath());
        settings.put(VaultCredentialProvider.RETRY_INTERVAL_MS, "1");
    }

    @AfterEach
    public void tearDown() {
        vault.close();
        VaultCredentialProvider.clearProviders();
    }

    private void writeToken(String token) throws IOException {
        Files.write(tokenFile.toPath(), (token + "\n").getBytes(StandardCharsets.UTF_8));
    }

    private VaultCredentialProvider provider(String path) throws IOException {
        return VaultCredentialProvider.get(URI.create(vault.uri(path)), settings::get);
    }

    @Test
    public void testReadsCredential() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        assertArrayEquals("s3cret".toCharArray(), provider("secret/zookeeper").getCredential(ALIAS));
    }

    @Test
    public void testAbsentAliasIsNull() throws Exception {
        vault.putSecret(DATA_PATH, "other", "s3cret");
        assertNull(provider("secret/zookeeper").getCredential(ALIAS));
        assertNull(provider("secret/zookeeper").getCredential("ssl.trustStore.password"));
    }

    @Test
    public void testFieldNamedByUri() throws Exception {
        vault.putSecret(DATA_PATH, "password", "s3cret");
        assertArrayEquals("s3cret".toCharArray(), provider("secret/zookeeper?key=password").getCredential(ALIAS));
    }

    @Test
    public void testScalarFieldIsText() throws Exception {
        vault.putSecretJson(DATA_PATH, "value", "12345");
        assertArrayEquals("12345".toCharArray(), provider("secret/zookeeper").getCredential(ALIAS));
    }

    @Test
    public void testObjectFieldIsRejected() throws Exception {
        vault.putSecretJson(DATA_PATH, "value", "{\"a\":1}");
        IOException e = assertThrows(IOException.class, () -> provider("secret/zookeeper").getCredential(ALIAS));
        assertThat(e.getMessage(), containsString("is not a string"));
    }

    @Test
    public void testUnservedMountFails() {
        IOException e = assertThrows(IOException.class, () -> provider("missing/zookeeper").getCredential(ALIAS));
        assertThat(e.getMessage(), containsString("404"));
    }

    @Test
    public void testRotatedTokenIsReadAfterRefusal() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        VaultCredentialProvider provider = provider("secret/zookeeper");
        provider.getCredential(ALIAS);

        vault.revokeToken(MockVault.TOKEN);
        vault.acceptToken("s.rotated");
        writeToken("s.rotated");
        assertArrayEquals("s3cret".toCharArray(), provider.getCredential(ALIAS));
    }

    @Test
    public void testRefusedTokenFails() throws Exception {
        vault.revokeToken(MockVault.TOKEN);
        IOException e = assertThrows(IOException.class, () -> provider("secret/zookeeper").getCredential(ALIAS));
        assertThat(e.getMessage(), containsString("403"));
    }

    @Test
    public void testTransientFailuresAreRetried() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        vault.fail(503, 2);
        assertArrayEquals("s3cret".toCharArray(), provider("secret/zookeeper").getCredential(ALIAS));
    }

    @Test
    public void testRetriesAreBounded() throws Exception {
        settings.put(VaultCredentialProvider.RETRY_COUNT, "1");
        vault.putSecret(DATA_PATH, "value", "s3cret");
        vault.fail(503, 5);
        IOException e = assertThrows(IOException.class, () -> provider("secret/zookeeper").getCredential(ALIAS));
        assertThat(e.getMessage(), containsString("failed after 2 attempts"));
    }

    @Test
    public void testClientErrorsAreNotRetried() throws Exception {
        vault.putSecret(DATA_PATH, "value", "s3cret");
        vault.fail(400, 1);
        assertThrows(IOException.class, () -> provider("secret/zookeeper").getCredential(ALIAS));
        assertEquals(0, vault.reads());
    }

    @Test
    public void testMissingTokenFileFails() {
        settings.put(VaultCredentialProvider.TOKEN_PATH, new File(tempDir, "absent").getAbsolutePath());
        assertThrows(IOException.class, () -> provider("secret/zookeeper").getCredential(ALIAS));
    }

    @Test
    public void testUnsupportedAuthMethod() {
        settings.put(VaultCredentialProvider.AUTH_METHOD, "approle");
        IOException e = assertThrows(IOException.class, () -> provider("secret/zookeeper"));
        assertThat(e.getMessage(), containsString("approle"));
    }

    @Test
    public void testInvalidNumber() {
        settings.put(VaultCredentialProvider.READ_TIMEOUT_MS, "soon");
        IOException e = assertThrows(IOException.class, () -> provider("secret/zookeeper"));
        assertThat(e.getMessage(), containsString(VaultCredentialProvider.READ_TIMEOUT_MS));
    }

    @Test
    public void testInvalidAlias() {
        assertThrows(IOException.class, () -> provider("secret/zookeeper").getCredential("../other"));
    }

    @Test
    public void testProvidersAreSharedBySettings() throws Exception {
        VaultCredentialProvider provider = provider("secret/zookeeper");
        assertSame(provider, provider("secret/zookeeper"));
        settings.put(VaultCredentialProvider.RETRY_COUNT, "5");
        assertNotSame(provider, provider("secret/zookeeper"));
    }

    @Test
    public void testTokenSources() throws Exception {
        Map<String, String> env = new HashMap<>();
        assertNull(new TokenVaultAuth(null, env::get).resolveToken());

        env.put(TokenVaultAuth.VAULT_TOKEN_ENV, " s.env ");
        assertEquals("s.env", new TokenVaultAuth(null, env::get).resolveToken());

        File credentials = new File(tempDir, "credentials");
        Files.createDirectories(credentials.toPath());
        Files.write(new File(credentials, TokenVaultAuth.SYSTEMD_CREDENTIAL_NAME).toPath(),
            "s.systemd".getBytes(StandardCharsets.UTF_8));
        env.put(TokenVaultAuth.CREDENTIALS_DIRECTORY_ENV, credentials.getAbsolutePath());
        assertEquals("s.systemd", new TokenVaultAuth(null, env::get).resolveToken());

        assertEquals(MockVault.TOKEN, new TokenVaultAuth(tokenFile.getAbsolutePath(), env::get).resolveToken());
    }

    @Test
    public void testTokenWithWhitespaceIsRejected() {
        Map<String, String> env = new HashMap<>();
        env.put(TokenVaultAuth.VAULT_TOKEN_ENV, "s.a b");
        IOException e = assertThrows(IOException.class, () -> new TokenVaultAuth(null, env::get).resolveToken());
        assertThat(e.getMessage(), containsString("whitespace"));
    }

    @Test
    public void testNoTokenFails() {
        IOException e = assertThrows(IOException.class,
            () -> new TokenVaultAuth(null, key -> null).authenticate(null));
        assertThat(e.getMessage(), containsString(VaultCredentialProvider.TOKEN_PATH));
    }
}
