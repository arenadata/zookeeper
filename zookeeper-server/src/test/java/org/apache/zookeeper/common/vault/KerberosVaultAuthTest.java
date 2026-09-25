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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import org.apache.zookeeper.Environment;
import org.apache.zookeeper.client.ZKClientConfig;
import org.apache.zookeeper.common.SecretUtils;
import org.apache.zookeeper.server.quorum.auth.MiniKdc;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class KerberosVaultAuthTest {

    private static final String CLIENT = "zookeeper/localhost";
    private static final String SERVER = "HTTP/localhost";
    private static final String NEGOTIATE = "Negotiate ";
    private static final String DATA_PATH = "secret/data/zookeeper/ssl.quorum.keyStore.password";
    private static final String TRUSTSTORE_DATA_PATH = "secret/data/zookeeper/ssl.quorum.trustStore.password";

    @TempDir
    static File tempDir;

    private static MiniKdc kdc;
    private static String previousJaasConfig;

    private MockVault vault;
    private Map<String, String> settings;

    @BeforeAll
    public static void startKdc() throws Exception {
        kdc = new MiniKdc(MiniKdc.createConf(), tempDir);
        kdc.start();
        File keytab = new File(tempDir, "vault.keytab");
        kdc.createPrincipal(keytab, CLIENT, SERVER);

        File jaas = new File(tempDir, "jaas.conf");
        try (PrintWriter out = new PrintWriter(new FileWriter(jaas))) {
            writeSection(out, "VaultClient", keytab, CLIENT, true);
            writeSection(out, "VaultServer", keytab, SERVER, false);
        }
        previousJaasConfig = System.setProperty(Environment.JAAS_CONF_KEY, jaas.getAbsolutePath());
        Configuration.getConfiguration().refresh();
    }

    private static void writeSection(PrintWriter out, String name, File keytab, String principal, boolean initiator) {
        out.println(name + " {");
        out.println("  com.sun.security.auth.module.Krb5LoginModule required");
        out.println("  useKeyTab=true");
        out.println("  keyTab=\"" + keytab.getAbsolutePath() + "\"");
        out.println("  storeKey=true");
        out.println("  useTicketCache=false");
        out.println("  doNotPrompt=true");
        out.println("  refreshKrb5Config=true");
        out.println("  isInitiator=" + initiator);
        out.println("  principal=\"" + principal + "@" + kdc.getRealm() + "\";");
        out.println("};");
    }

    @AfterAll
    public static void stopKdc() {
        if (previousJaasConfig == null) {
            System.clearProperty(Environment.JAAS_CONF_KEY);
        } else {
            System.setProperty(Environment.JAAS_CONF_KEY, previousJaasConfig);
        }
        Configuration.getConfiguration().refresh();
        if (kdc != null) {
            kdc.stop();
        }
    }

    @BeforeEach
    public void setUp() throws IOException {
        vault = new MockVault();
        vault.setLoginHandler(KerberosVaultAuthTest::login);
        vault.revokeToken(MockVault.TOKEN);
        vault.putSecret(DATA_PATH, "value", "s3cret");
        vault.putSecret(TRUSTSTORE_DATA_PATH, "value", "tr0st");
        settings = new HashMap<>();
        settings.put(VaultCredentialProvider.AUTH_METHOD, VaultCredentialProvider.AUTH_METHOD_KERBEROS);
        settings.put(VaultCredentialProvider.KERBEROS_LOGIN_CONTEXT, "VaultClient");
        settings.put(VaultCredentialProvider.KERBEROS_SERVICE_PRINCIPAL, "HTTP/_HOST@" + kdc.getRealm());
        settings.put(VaultCredentialProvider.RETRY_INTERVAL_MS, "1");
    }

    @AfterEach
    public void tearDown() {
        vault.close();
        VaultCredentialProvider.clearProviders();
    }

    private char[] read() throws IOException {
        return read(vault.uri("secret/zookeeper"), "ssl.quorum.keyStore.password");
    }

    private char[] read(String uri, String alias) throws IOException {
        return VaultCredentialProvider.get(URI.create(uri), settings::get).getCredential(alias);
    }

    private static String login(String authorization) throws Exception {
        return (CLIENT + "@" + kdc.getRealm()).equals(acceptSpnego(authorization)) ? "s.kerberos" : null;
    }

    /**
     * Accepts a SPNEGO token as the Vault service principal and returns the client principal.
     */
    private static String acceptSpnego(String authorization) throws Exception {
        if (authorization == null || !authorization.startsWith(NEGOTIATE)) {
            throw new IOException("missing Negotiate header: " + authorization);
        }
        byte[] token = Base64.getDecoder().decode(authorization.substring(NEGOTIATE.length()));
        LoginContext lc = new LoginContext("VaultServer");
        lc.login();
        try {
            return Subject.doAs(lc.getSubject(), (PrivilegedExceptionAction<String>) () -> {
                GSSManager manager = GSSManager.getInstance();
                Oid spnego = new Oid("1.3.6.1.5.5.2");
                Oid krb5 = new Oid("1.2.840.113554.1.2.2");
                GSSCredential credential = manager.createCredential(
                    manager.createName(SERVER + "@" + kdc.getRealm(), new Oid("1.2.840.113554.1.2.2.1")),
                    GSSCredential.INDEFINITE_LIFETIME, new Oid[] {spnego, krb5}, GSSCredential.ACCEPT_ONLY);
                GSSContext context = manager.createContext(credential);
                try {
                    context.acceptSecContext(token, 0, token.length);
                    if (!context.isEstablished()) {
                        throw new GSSException(GSSException.DEFECTIVE_TOKEN);
                    }
                    return context.getSrcName().toString();
                } finally {
                    context.dispose();
                }
            });
        } finally {
            lc.logout();
        }
    }

    @Test
    public void testLogsInWithSpnego() throws Exception {
        assertArrayEquals("s3cret".toCharArray(), read());
        assertEquals(Collections.singletonList(null), vault.loginRoles());
    }

    @Test
    public void testLogsInAgainWhenTheTokenIsRefused() throws Exception {
        read();
        vault.revokeToken("s.kerberos");
        assertArrayEquals("tr0st".toCharArray(), read(vault.uri("secret/zookeeper"), "ssl.quorum.trustStore.password"));
        assertEquals(2, vault.loginRoles().size());
    }

    @Test
    public void testHostOfServicePrincipalIsLowerCased() throws Exception {
        assertArrayEquals("s3cret".toCharArray(),
            read("vault://http@LocalHost:" + vault.port() + "/secret/zookeeper", "ssl.quorum.keyStore.password"));
    }

    @Test
    public void testFollowsLoginRedirectWithTheToken() throws Exception {
        try (MockVault active = new MockVault()) {
            active.setLoginHandler(KerberosVaultAuthTest::login);
            vault.redirectLoginTo(active);
            vault.acceptToken("s.kerberos");
            assertArrayEquals("s3cret".toCharArray(), read());
            assertEquals(1, active.loginRoles().size());
            assertEquals(0, vault.loginRoles().size());
        }
    }

    @Test
    public void testSendsRole() throws Exception {
        settings.put(VaultCredentialProvider.KERBEROS_ROLE, "zookeeper");
        read();
        assertEquals(Collections.singletonList("zookeeper"), vault.loginRoles());
    }

    @Test
    public void testUnknownLoginContextFails() {
        settings.put(VaultCredentialProvider.KERBEROS_LOGIN_CONTEXT, "Missing");
        IOException e = assertThrows(IOException.class, this::read);
        assertThat(e.getMessage(), containsString("JAAS section Missing"));
    }

    @Test
    public void testRefusedLoginFails() {
        vault.setLoginHandler(authorization -> null);
        IOException e = assertThrows(IOException.class, this::read);
        assertThat(e.getMessage(), containsString("403"));
        assertEquals(1, vault.loginRoles().size());
    }

    @Test
    public void testMountPath() {
        settings.put(VaultCredentialProvider.KERBEROS_MOUNT_PATH, "/auth/krb/");
        assertThrows(IOException.class, this::read);
        assertTrue(vault.requests().contains("POST /v1/auth/krb/login"), vault.requests().toString());
    }

    private ZKClientConfig clientConfig() {
        ZKClientConfig config = new ZKClientConfig();
        config.setProperty(SecretUtils.CREDENTIAL_PROVIDER_PATH, vault.uri("secret/zookeeper"));
        config.setProperty(VaultCredentialProvider.AUTH_METHOD, VaultCredentialProvider.AUTH_METHOD_KERBEROS);
        config.setProperty(VaultCredentialProvider.KERBEROS_SERVICE_PRINCIPAL, "HTTP/_HOST@" + kdc.getRealm());
        return config;
    }

    @Test
    public void testClientLogsInWithItsJaasSection() throws Exception {
        ZKClientConfig config = clientConfig();
        config.setProperty(ZKClientConfig.LOGIN_CONTEXT_NAME_KEY, "VaultClient");
        assertArrayEquals("s3cret".toCharArray(), SecretUtils.getCredential(config, "ssl.quorum.keyStore.password"));

        IOException e = assertThrows(IOException.class,
            () -> SecretUtils.getCredential(clientConfig(), "ssl.quorum.keyStore.password"));
        assertThat(e.getMessage() + e.getCause(), containsString("JAAS section Client"));
    }
}
