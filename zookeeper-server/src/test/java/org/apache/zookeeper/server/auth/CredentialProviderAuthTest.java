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

package org.apache.zookeeper.server.auth;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.servlet.http.HttpServletRequest;
import org.apache.zookeeper.common.SecretUtils;
import org.apache.zookeeper.common.vault.MockVault;
import org.apache.zookeeper.common.vault.VaultCredentialProvider;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.ServerConfig;
import org.apache.zookeeper.server.ZooKeeperServerMain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class CredentialProviderAuthTest {

    private static final String SUPER_DIGEST = "zookeeper.DigestAuthenticationProvider.superDigest";
    private static final String SUPER_PASSWORD = "zookeeper.SASLAuthenticationProvider.superPassword";
    private static final Id SUPER = new Id("super", "");

    @TempDir
    File tempDir;

    private MockVault vault;

    @BeforeEach
    public void setUp() throws Exception {
        vault = new MockVault();
        File tokenFile = new File(tempDir, "vault-token");
        Files.write(tokenFile.toPath(), MockVault.TOKEN.getBytes(UTF_8));
        System.setProperty(SecretUtils.CREDENTIAL_PROVIDER_PATH, vault.uri("secret/zookeeper"));
        System.setProperty(VaultCredentialProvider.TOKEN_PATH, tokenFile.getAbsolutePath());
        System.setProperty(VaultCredentialProvider.RETRY_INTERVAL_MS, "1");
    }

    @AfterEach
    public void tearDown() {
        System.clearProperty(SecretUtils.CREDENTIAL_PROVIDER_PATH);
        System.clearProperty(VaultCredentialProvider.TOKEN_PATH);
        System.clearProperty(VaultCredentialProvider.RETRY_INTERVAL_MS);
        System.clearProperty(VaultCredentialProvider.RETRY_COUNT);
        System.clearProperty(SUPER_DIGEST);
        System.clearProperty(SUPER_PASSWORD);
        vault.close();
    }

    private static List<Id> authenticate(String idPassword) {
        return new DigestAuthenticationProvider().handleAuthentication((HttpServletRequest) null,
            idPassword.getBytes(UTF_8));
    }

    @Test
    public void testSuperDigestFromProvider() throws Exception {
        System.setProperty(SUPER_DIGEST, DigestAuthenticationProvider.generateDigest("super:property"));
        vault.putSecret("secret/data/zookeeper/DigestAuthenticationProvider.superDigest", "value",
            DigestAuthenticationProvider.generateDigest("super:vault"));
        assertTrue(authenticate("super:vault").contains(SUPER));
        assertFalse(authenticate("super:property").contains(SUPER));
    }

    @Test
    public void testSuperDigestFromPropertyWhenProviderHasNone() throws Exception {
        System.setProperty(SUPER_DIGEST, DigestAuthenticationProvider.generateDigest("super:property"));
        assertTrue(authenticate("super:property").contains(SUPER));
    }

    @Test
    public void testSuperDigestFailsClosed() throws Exception {
        System.setProperty(SUPER_DIGEST, DigestAuthenticationProvider.generateDigest("super:property"));
        vault.revokeToken(MockVault.TOKEN);
        assertFalse(authenticate("super:property").contains(SUPER));
    }

    @Test
    public void testServerDoesNotStartWhileVaultIsUnreachable() throws Exception {
        System.setProperty(SecretUtils.CREDENTIAL_PROVIDER_PATH, "vault://http@localhost:1/secret/zookeeper");
        System.setProperty(VaultCredentialProvider.RETRY_COUNT, "0");
        ServerConfig config = new ServerConfig();
        config.parse(new String[] {"0", tempDir.getAbsolutePath()});
        assertThrows(IOException.class, () -> new ZooKeeperServerMain().runFromConfig(config));
    }

    private static char[] superPassword(SaslServerCallbackHandler handler) throws Exception {
        PasswordCallback pc = new PasswordCallback("password", false);
        handler.handle(new Callback[] {new NameCallback("user", "super"), pc});
        return pc.getPassword();
    }

    @Test
    public void testSuperPasswordFromProvider() throws Exception {
        System.setProperty(SUPER_PASSWORD, "property");
        vault.putSecret("secret/data/zookeeper/SASLAuthenticationProvider.superPassword", "value", "vault");
        Map<String, String> credentials = Collections.singletonMap("super", "jaas");
        char[] fromProvider = SaslServerCallbackHandler.superPasswordFromCredentialProvider();
        assertArrayEquals("vault".toCharArray(), fromProvider);
        assertArrayEquals("vault".toCharArray(),
            superPassword(new SaslServerCallbackHandler(credentials, fromProvider, null, null, null)));
    }

    @Test
    public void testSuperPasswordFromPropertyWhenProviderHasNone() throws Exception {
        System.setProperty(SUPER_PASSWORD, "property");
        Map<String, String> credentials = Collections.singletonMap("super", "jaas");
        char[] fromProvider = SaslServerCallbackHandler.superPasswordFromCredentialProvider();
        assertNull(fromProvider);
        assertArrayEquals("property".toCharArray(),
            superPassword(new SaslServerCallbackHandler(credentials, fromProvider, null, null, null)));
    }
}
