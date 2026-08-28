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

package org.apache.zookeeper.test;

import static org.apache.zookeeper.client.ZKClientConfig.ENABLE_CLIENT_SASL_KEY;
import static org.apache.zookeeper.client.ZKClientConfig.LOGIN_CONTEXT_NAME_KEY;
import static org.apache.zookeeper.client.ZKClientConfig.ZOOKEEPER_SERVER_PRINCIPAL;
import static org.apache.zookeeper.client.ZKClientConfig.ZOOKEEPER_SERVER_REALM;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import javax.security.auth.login.Configuration;
import org.apache.commons.io.FileUtils;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.Environment;
import org.apache.zookeeper.ZooDefs.Ids;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.data.ClientInfo;
import org.apache.zookeeper.proto.GetDelegationTokenResponse;
import org.apache.zookeeper.server.quorum.auth.KerberosTestUtils;
import org.apache.zookeeper.server.quorum.auth.MiniKdc;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.apache.zookeeper.server.token.DelegationTokenStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * GSSAPI and delegation token clients coexisting on one Kerberized server:
 * the lazy mechanism selection lets the same server negotiate GSSAPI with a
 * Kerberos client and DIGEST-MD5 with a token client, a GSSAPI session mints
 * the token, and the token session is authorized as the Kerberos principal.
 */
public class KerberosTokenCoexistenceTest extends ClientBase {

    private static final String DIGEST_LOGIN_MODULE = "org.apache.zookeeper.server.auth.DigestLoginModule";
    private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";

    private static MiniKdc kdc;
    private static File kdcWorkDir;

    private File keytabFile;
    private File saslConfFile;
    private File secretFile;

    @BeforeAll
    public static void setupKdc() throws Exception {
        kdcWorkDir = createEmptyTestDir();
        Properties conf = MiniKdc.createConf();
        conf.setProperty("debug", "true");
        kdc = new MiniKdc(conf, kdcWorkDir);
        kdc.start();
    }

    @AfterAll
    public static void tearDownKdc() {
        if (kdc != null) {
            kdc.stop();
        }
        FileUtils.deleteQuietly(kdcWorkDir);
    }

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        keytabFile = new File(KerberosTestUtils.getKeytabFile());
        String clientPrincipal = KerberosTestUtils.getClientPrincipal();
        String serverPrincipal = KerberosTestUtils.getServerPrincipal();
        clientPrincipal = clientPrincipal.substring(0, clientPrincipal.lastIndexOf("@"));
        serverPrincipal = serverPrincipal.substring(0, serverPrincipal.lastIndexOf("@"));
        kdc.createPrincipal(keytabFile, clientPrincipal, serverPrincipal);

        File tmpDir = createTmpDir();
        secretFile = new File(tmpDir, "master.key");
        Files.write(secretFile.toPath(), "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));
        saslConfFile = new File(tmpDir, "jaas.conf");
        writeSaslConfig("-", "-");

        System.setProperty(Environment.JAAS_CONF_KEY, saslConfFile.getAbsolutePath());
        // the token client uses DIGEST-MD5, which is disabled in FIPS mode
        System.setProperty(org.apache.zookeeper.common.X509Util.FIPS_MODE_PROPERTY, "false");
        System.setProperty(ZOOKEEPER_SERVER_PRINCIPAL, KerberosTestUtils.getServerPrincipal());
        System.setProperty(ENABLE_CLIENT_SASL_KEY, "true");
        System.setProperty(ZOOKEEPER_SERVER_REALM, KerberosTestUtils.getRealm());
        System.setProperty(LOGIN_CONTEXT_NAME_KEY, "ClientUsingKerberos");
        System.setProperty("zookeeper.authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider");
        System.setProperty(SaslTestUtil.requireSASLAuthProperty, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE, secretFile.getAbsolutePath());

        Configuration.getConfiguration().refresh();
        super.setUp();
    }

    @AfterEach
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        FileUtils.deleteQuietly(keytabFile);
        FileUtils.deleteQuietly(saslConfFile);
        System.clearProperty(Environment.JAAS_CONF_KEY);
        System.clearProperty(org.apache.zookeeper.common.X509Util.FIPS_MODE_PROPERTY);
        System.clearProperty(ZOOKEEPER_SERVER_PRINCIPAL);
        System.clearProperty(ENABLE_CLIENT_SASL_KEY);
        System.clearProperty(ZOOKEEPER_SERVER_REALM);
        System.clearProperty(LOGIN_CONTEXT_NAME_KEY);
        System.clearProperty("zookeeper.authProvider.1");
        System.clearProperty(SaslTestUtil.requireSASLAuthProperty);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE);
    }

    private void writeSaslConfig(String tokenUser, String tokenPassword) throws Exception {
        try (PrintWriter saslConf = new PrintWriter(new FileWriter(saslConfFile))) {
            saslConf.println("Server {");
            saslConf.println("  " + KRB5_LOGIN_MODULE + " required");
            saslConf.println("  storeKey=\"true\"");
            saslConf.println("  useTicketCache=\"false\"");
            saslConf.println("  useKeyTab=\"true\"");
            saslConf.println("  doNotPrompt=\"true\"");
            saslConf.println("  refreshKrb5Config=\"true\"");
            saslConf.println("  keyTab=\"" + keytabFile.getAbsolutePath() + "\"");
            saslConf.println("  principal=\"" + KerberosTestUtils.getServerPrincipal() + "\";");
            saslConf.println("};");
            saslConf.println("ClientUsingKerberos {");
            saslConf.println("  " + KRB5_LOGIN_MODULE + " required");
            saslConf.println("  storeKey=\"false\"");
            saslConf.println("  useTicketCache=\"false\"");
            saslConf.println("  useKeyTab=\"true\"");
            saslConf.println("  doNotPrompt=\"true\"");
            saslConf.println("  refreshKrb5Config=\"true\"");
            saslConf.println("  keyTab=\"" + keytabFile.getAbsolutePath() + "\"");
            saslConf.println("  principal=\"" + KerberosTestUtils.getClientPrincipal() + "\";");
            saslConf.println("};");
            saslConf.println("ClientUsingToken {");
            saslConf.println("  " + DIGEST_LOGIN_MODULE + " required");
            saslConf.println("  username=\"" + tokenUser + "\"");
            saslConf.println("  password=\"" + tokenPassword + "\";");
            saslConf.println("};");
        }
    }

    @Test
    public void testGssapiAndTokenClientsCoexist() throws Exception {
        // GSSAPI client works through the lazy mechanism selection and mints a token
        GetDelegationTokenResponse token;
        String owner;
        try (ZooKeeper gssapiClient = createClient()) {
            gssapiClient.create("/krb-gssapi-test", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
            owner = gssapiClient.getACL("/krb-gssapi-test", null).get(0).getId().getId();
            assertTrue(owner.startsWith("zkclient"), "unexpected GSSAPI principal: " + owner);
            token = gssapiClient.getDelegationToken("", 0);
        }

        writeSaslConfig(
            Base64.getEncoder().encodeToString(token.getIdentifier()),
            Base64.getEncoder().encodeToString(token.getPassword()));
        Configuration.getConfiguration().refresh();

        // DIGEST-MD5 token client against the same Kerberized server
        System.setProperty(LOGIN_CONTEXT_NAME_KEY, "ClientUsingToken");
        try (ZooKeeper tokenClient = createClient()) {
            tokenClient.create("/krb-token-test", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
            // authorized as the Kerberos principal that minted the token
            assertEquals(owner, tokenClient.getACL("/krb-token-test", null).get(0).getId().getId());

            List<ClientInfo> clientInfo = tokenClient.whoAmI();
            assertTrue(clientInfo.stream().anyMatch(
                info -> "sasl".equals(info.getAuthScheme()) && owner.equals(info.getUser())));
            assertTrue(clientInfo.stream().anyMatch(
                info -> DelegationTokenStore.TOKEN_AUTH_SCHEME.equals(info.getAuthScheme())));
        } finally {
            System.setProperty(LOGIN_CONTEXT_NAME_KEY, "ClientUsingKerberos");
        }

        // and GSSAPI keeps working afterwards
        try (ZooKeeper gssapiClient = createClient()) {
            gssapiClient.create("/krb-gssapi-test-2", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
        }
    }

}
