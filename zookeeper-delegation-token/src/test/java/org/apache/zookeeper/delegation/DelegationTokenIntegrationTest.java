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

package org.apache.zookeeper.delegation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooDefs.Ids;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.apache.zookeeper.test.SaslAuthDigestTestBase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Full path through the Hadoop integration: obtain a live token as a SASL
 * client, decode it via the ServiceLoader-registered identifier, authenticate
 * a ZooKeeper client with the token JAAS glue, renew and cancel through the
 * Hadoop Token API (ServiceLoader-registered renewer).
 */
public class DelegationTokenIntegrationTest extends SaslAuthDigestTestBase {

    private static final String LOGIN_MODULE = "org.apache.zookeeper.server.auth.DigestLoginModule";
    private static final String CLIENT_CONFIG_PROP = "zookeeper.sasl.clientconfig";
    private static final String SERVICE = "test-zk";

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        File tmpDir = createTmpDir();
        File secretFile = new File(tmpDir, "master.key");
        Files.write(secretFile.toPath(), "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));

        File jaasFile = new File(tmpDir, "jaas.conf");
        try (FileWriter writer = new FileWriter(jaasFile)) {
            writer.write(""
                + "Server {\n"
                + "    " + LOGIN_MODULE + " required\n"
                + "    user_alice=\"alicepass\"\n"
                + "    user_bob=\"bobpass\";\n"
                + "};\n"
                + "Client {\n"
                + "    " + LOGIN_MODULE + " required\n"
                + "    username=\"alice\"\n"
                + "    password=\"alicepass\";\n"
                + "};\n"
                + "ClientBob {\n"
                + "    " + LOGIN_MODULE + " required\n"
                + "    username=\"bob\"\n"
                + "    password=\"bobpass\";\n"
                + "};\n");
        }

        System.setProperty("zookeeper.authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider");
        System.setProperty("java.security.auth.login.config", jaasFile.getAbsolutePath());
        System.setProperty("zookeeper.allowSaslFailedClients", "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE, secretFile.getAbsolutePath());
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_RENEW_INTERVAL, "3600000");
    }

    @AfterAll
    public static void tearDownAfterClass() {
        System.clearProperty("zookeeper.authProvider.1");
        System.clearProperty("java.security.auth.login.config");
        System.clearProperty("zookeeper.allowSaslFailedClients");
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_RENEW_INTERVAL);
    }

    @AfterEach
    public void clearClientSection() {
        System.clearProperty(CLIENT_CONFIG_PROP);
    }

    @Test
    public void testObtainAuthenticateRenewCancel() throws Exception {
        // issued as alice (default Client JAAS section)
        ZooKeeperDelegationTokens.ObtainedToken obtained =
            ZooKeeperDelegationTokens.obtainToken(hostPort, "bob", 0, SERVICE);
        Token<ZooKeeperDelegationTokenIdentifier> token = obtained.getToken();
        assertTrue(obtained.getExpiryTime() > System.currentTimeMillis());
        assertEquals(ZooKeeperDelegationTokenIdentifier.KIND_NAME, token.getKind());

        // decodeIdentifier resolves the identifier class via ServiceLoader
        TokenIdentifier decoded = token.decodeIdentifier();
        assertTrue(decoded instanceof ZooKeeperDelegationTokenIdentifier);
        ZooKeeperDelegationTokenIdentifier ident = (ZooKeeperDelegationTokenIdentifier) decoded;
        assertEquals("alice", ident.getOwner().toString());
        assertEquals("bob", ident.getRenewer().toString());
        assertTrue(ident.getMaxDate() > System.currentTimeMillis());

        Credentials credentials = new Credentials();
        credentials.addToken(new Text(SERVICE), token);
        assertSame(token, ZooKeeperDelegationTokens.selectToken(credentials, SERVICE));
        assertNull(ZooKeeperDelegationTokens.selectToken(credentials, "other-service"));

        // a plain ZooKeeper client authenticates with the token via JAAS glue
        javax.security.auth.login.Configuration previous =
            ZooKeeperDelegationTokens.installTokenJaasConfiguration(token);
        try {
            try (ZooKeeper tokenClient = createClient(new CountdownWatcher())) {
                tokenClient.create("/dt-integration-test", "data".getBytes(StandardCharsets.UTF_8),
                    Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
                assertEquals("alice", tokenClient.getACL("/dt-integration-test", null).get(0).getId().getId());
            }

            // renew and cancel through the Hadoop Token API as bob, resolving
            // the renewer via ServiceLoader and the quorum via configuration
            org.apache.hadoop.conf.Configuration conf = new org.apache.hadoop.conf.Configuration(false);
            conf.set(ZooKeeperTokenRenewer.QUORUM_CONF_PREFIX + SERVICE, hostPort);
            System.setProperty(CLIENT_CONFIG_PROP, "ClientBob");
            long newExpiry = token.renew(conf);
            assertTrue(newExpiry >= obtained.getExpiryTime());

            token.cancel(conf);
            System.clearProperty(CLIENT_CONFIG_PROP);

            // the cancelled token no longer authenticates
            try (ZooKeeper cancelled = createClient(new CountdownWatcher())) {
                assertThrows(KeeperException.class, () ->
                    cancelled.create("/dt-cancelled-test", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT));
            }
        } finally {
            javax.security.auth.login.Configuration.setConfiguration(previous);
        }
    }

}
