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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import javax.security.auth.login.Configuration;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooDefs.Ids;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.proto.GetDelegationTokenResponse;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Token store persistence: an issued token keeps authenticating after the
 * server restarts and reloads the store from snapshot/txn log, and stays
 * renewable; cancellation works after the restart too.
 */
public class DelegationTokenRestartTest extends SaslAuthDigestTestBase {

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
        System.setProperty("zookeeper.allowSaslFailedClients", "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE, secretFile.getAbsolutePath());
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_RENEW_INTERVAL, "3600000");
        writeJaasFile("-", "-");
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
        return createClient(new CountdownWatcher());
    }

    @Test
    public void testTokenSurvivesRestart() throws Exception {
        GetDelegationTokenResponse token;
        try (ZooKeeper alice = client(null)) {
            token = alice.getDelegationToken("bob", 0);
        }
        writeJaasFile(
            Base64.getEncoder().encodeToString(token.getIdentifier()),
            Base64.getEncoder().encodeToString(token.getPassword()));

        try (ZooKeeper tokenClient = client("ClientToken")) {
            tokenClient.create("/dt-restart-before", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
        }

        stopServer();
        startServer();

        // the store is reloaded from disk: the token still authenticates
        try (ZooKeeper tokenClient = client("ClientToken")) {
            tokenClient.create("/dt-restart-after", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
            assertNotNull(tokenClient.exists("/dt-restart-before", false));
        }

        // and stays renewable and cancellable
        try (ZooKeeper bob = client("ClientBob")) {
            assertTrue(bob.renewDelegationToken(token.getIdentifier()) >= token.getExpiryTime());
            bob.cancelDelegationToken(token.getIdentifier());
        }

        try (ZooKeeper cancelled = client("ClientToken")) {
            assertThrows(KeeperException.class, () ->
                cancelled.create("/dt-restart-cancelled", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT));
        }
    }

}
