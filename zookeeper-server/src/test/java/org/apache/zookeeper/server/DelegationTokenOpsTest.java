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

package org.apache.zookeeper.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.List;
import javax.security.auth.login.Configuration;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.data.ClientInfo;
import org.apache.zookeeper.proto.GetDelegationTokenResponse;
import org.apache.zookeeper.server.token.DelegationTokenCleanupManager;
import org.apache.zookeeper.server.token.DelegationTokenIdentifier;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.apache.zookeeper.server.token.DelegationTokenStore;
import org.apache.zookeeper.server.token.DelegationTokenTool;
import org.apache.zookeeper.test.SaslAuthDigestTestBase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * End-to-end coverage of the delegation token opcodes: issuance, chained
 * issuance ban, renew permissions, cancel and expiry cleanup.
 */
public class DelegationTokenOpsTest extends SaslAuthDigestTestBase {

    private static final String LOGIN_MODULE = "org.apache.zookeeper.server.auth.DigestLoginModule";
    private static final String CLIENT_CONFIG_PROP = "zookeeper.sasl.clientconfig";

    private static File jaasFile;

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        File tmpDir = createTmpDir();
        File secretFile = new File(tmpDir, "master.key");
        Files.write(secretFile.toPath(), "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));
        jaasFile = new File(tmpDir, "jaas.conf");
        System.setProperty("zookeeper.authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider");
        System.setProperty("java.security.auth.login.config", jaasFile.getAbsolutePath());
        writeJaasFile("-", "-");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE, secretFile.getAbsolutePath());
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_RENEW_INTERVAL, "3600000");
    }

    @AfterAll
    public static void tearDownAfterClass() {
        System.clearProperty("zookeeper.authProvider.1");
        System.clearProperty("java.security.auth.login.config");
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_RENEW_INTERVAL);
    }

    @AfterEach
    public void clearClientSection() {
        System.clearProperty(CLIENT_CONFIG_PROP);
    }

    private static void writeJaasFile(String tokenUser, String tokenPassword) throws Exception {
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
                + "};\n"
                + "ClientToken {\n"
                + "    " + LOGIN_MODULE + " required\n"
                + "    username=\"" + tokenUser + "\"\n"
                + "    password=\"" + tokenPassword + "\";\n"
                + "};\n");
        }
        Configuration.getConfiguration().refresh();
    }

    private ZooKeeper client(String section) throws Exception {
        if (section == null) {
            System.clearProperty(CLIENT_CONFIG_PROP);
        } else {
            System.setProperty(CLIENT_CONFIG_PROP, section);
        }
        CountdownWatcher watcher = new CountdownWatcher();
        return createClient(watcher);
    }

    private static void installTokenClientSection(GetDelegationTokenResponse token) throws Exception {
        writeJaasFile(
            Base64.getEncoder().encodeToString(token.getIdentifier()),
            Base64.getEncoder().encodeToString(token.getPassword()));
    }

    @Test
    public void testIssueAndAuthenticateWithToken() throws Exception {
        GetDelegationTokenResponse token;
        try (ZooKeeper alice = client(null)) {
            token = alice.getDelegationToken("bob", 0);
        }
        assertTrue(token.getIdentifier().length > 0);
        assertEquals(32, token.getPassword().length);
        assertTrue(token.getExpiryTime() > System.currentTimeMillis());

        DelegationTokenIdentifier ident = DelegationTokenIdentifier.fromBytes(token.getIdentifier());
        assertEquals("alice", ident.getOwner());
        assertEquals("bob", ident.getRenewer());

        installTokenClientSection(token);
        try (ZooKeeper tokenClient = client("ClientToken")) {
            List<ClientInfo> clientInfo = tokenClient.whoAmI();
            assertTrue(clientInfo.stream().anyMatch(
                info -> "sasl".equals(info.getAuthScheme()) && "alice".equals(info.getUser())));
            assertTrue(clientInfo.stream().anyMatch(
                info -> DelegationTokenStore.TOKEN_AUTH_SCHEME.equals(info.getAuthScheme())),
                "token-authenticated session must carry the token auth marker");

            // a delegation token must not mint further tokens
            assertThrows(KeeperException.NoAuthException.class,
                () -> tokenClient.getDelegationToken("bob", 0));
        }
    }

    @Test
    public void testUnauthenticatedClientCannotIssue() throws Exception {
        System.setProperty("zookeeper.sasl.client", "false");
        try (ZooKeeper plain = client(null)) {
            assertThrows(KeeperException.NoAuthException.class,
                () -> plain.getDelegationToken("bob", 0));
        } finally {
            System.clearProperty("zookeeper.sasl.client");
        }
    }

    @Test
    public void testRenewPermissionsAndCancel() throws Exception {
        GetDelegationTokenResponse token;
        try (ZooKeeper alice = client(null)) {
            token = alice.getDelegationToken("bob", 0);

            // owner is not the renewer
            assertThrows(KeeperException.NoAuthException.class,
                () -> alice.renewDelegationToken(token.getIdentifier()));
        }

        try (ZooKeeper bob = client("ClientBob")) {
            long newExpiry = bob.renewDelegationToken(token.getIdentifier());
            assertTrue(newExpiry >= token.getExpiryTime());
        }

        DelegationTokenIdentifier ident = DelegationTokenIdentifier.fromBytes(token.getIdentifier());
        String tokenPath = DelegationTokenStore.pathOf(ident.getSequenceNumber());
        try (ZooKeeper alice = client(null)) {
            assertNotNull(alice.exists(tokenPath, false));
            alice.cancelDelegationToken(token.getIdentifier());
            assertNull(alice.exists(tokenPath, false));
        }

        try (ZooKeeper bob = client("ClientBob")) {
            assertThrows(KeeperException.NoNodeException.class,
                () -> bob.renewDelegationToken(token.getIdentifier()));
        }
    }

    @Test
    public void testToolIssuesLiveToken() throws Exception {
        ByteArrayOutputStream toolOutput = new ByteArrayOutputStream();
        DelegationTokenTool.run(
            new String[]{"--server", hostPort, "--renewer", "bob"},
            new PrintStream(toolOutput, true, "UTF-8"));
        String output = toolOutput.toString("UTF-8");

        byte[] identifier = Base64.getDecoder().decode(valueOf(output, "Identifier:"));
        byte[] password = Base64.getDecoder().decode(valueOf(output, "Password:"));
        DelegationTokenIdentifier ident = DelegationTokenIdentifier.fromBytes(identifier);
        assertEquals("alice", ident.getOwner());
        assertEquals("bob", ident.getRenewer());

        GetDelegationTokenResponse token = new GetDelegationTokenResponse(identifier, password, 0);
        installTokenClientSection(token);
        try (ZooKeeper tokenClient = client("ClientToken")) {
            List<ClientInfo> clientInfo = tokenClient.whoAmI();
            assertTrue(clientInfo.stream().anyMatch(
                info -> "sasl".equals(info.getAuthScheme()) && "alice".equals(info.getUser())));
        }
    }

    private static String valueOf(String output, String label) {
        for (String line : output.split("\n")) {
            if (line.startsWith(label)) {
                return line.substring(label.length()).trim();
            }
        }
        throw new IllegalStateException("no '" + label + "' line in tool output:\n" + output);
    }

    @Test
    public void testExpiredTokenRemovedByCleanup() throws Exception {
        GetDelegationTokenResponse token;
        try (ZooKeeper alice = client(null)) {
            token = alice.getDelegationToken("bob", 1500);
        }
        DelegationTokenIdentifier ident = DelegationTokenIdentifier.fromBytes(token.getIdentifier());
        String tokenPath = DelegationTokenStore.pathOf(ident.getSequenceNumber());

        long waitUntil = token.getExpiryTime() + 200;
        while (System.currentTimeMillis() < waitUntil) {
            Thread.sleep(100);
        }

        ZooKeeperServer zks = serverFactory.getZooKeeperServer();
        DelegationTokenCleanupManager cleanup =
            new DelegationTokenCleanupManager(zks.getZKDatabase(), zks.firstProcessor, 3600000);
        cleanup.checkTokens();

        try (ZooKeeper alice = client(null)) {
            long deadline = System.currentTimeMillis() + 5000;
            while (alice.exists(tokenPath, false) != null && System.currentTimeMillis() < deadline) {
                Thread.sleep(100);
            }
            assertNull(alice.exists(tokenPath, false), "expired token node must be removed by cleanup");
        }
    }

}
