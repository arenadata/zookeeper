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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
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
 * Delegation tokens on a real quorum: issuance through a follower (the
 * request is forwarded to the leader with its auth info), the replicated
 * store authenticating the token on every ensemble member, and cancellation
 * propagating quorum-wide.
 */
public class DelegationTokenQuorumTest extends QuorumBase {

    private static final String LOGIN_MODULE = "org.apache.zookeeper.server.auth.DigestLoginModule";
    private static final String CLIENT_CONFIG_PROP = "zookeeper.sasl.clientconfig";

    private static File jaasFile;

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        File tmpDir = createTmpDir();
        File secretFile = new File(tmpDir, "master.key");
        Files.write(secretFile.toPath(), "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));
        jaasFile = new File(tmpDir, "jaas.conf");
        // DIGEST-MD5 is disabled in FIPS mode
        System.setProperty(org.apache.zookeeper.common.X509Util.FIPS_MODE_PROPERTY, "false");
        System.setProperty("zookeeper.authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider");
        System.setProperty("java.security.auth.login.config", jaasFile.getAbsolutePath());
        System.setProperty("zookeeper.allowSaslFailedClients", "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE, secretFile.getAbsolutePath());
        writeJaasFile("-", "-");
    }

    @AfterAll
    public static void tearDownAfterClass() {
        System.clearProperty(org.apache.zookeeper.common.X509Util.FIPS_MODE_PROPERTY);
        System.clearProperty("zookeeper.authProvider.1");
        System.clearProperty("java.security.auth.login.config");
        System.clearProperty("zookeeper.allowSaslFailedClients");
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE);
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

    private ZooKeeper client(String section, String hp) throws Exception {
        if (section == null) {
            System.clearProperty(CLIENT_CONFIG_PROP);
        } else {
            System.setProperty(CLIENT_CONFIG_PROP, section);
        }
        return createClient(new CountdownWatcher(), hp);
    }

    @Test
    public void testTokenAcrossQuorum() throws Exception {
        int leaderPort = getLeaderClientPort();
        List<Integer> ports = Arrays.asList(portClient1, portClient2, portClient3, portClient4, portClient5);
        int followerPort = ports.stream().filter(p -> p != leaderPort).findFirst().get();

        // issue through a follower: the request is forwarded to the leader
        // together with the session's auth info
        GetDelegationTokenResponse token;
        try (ZooKeeper alice = client(null, "127.0.0.1:" + followerPort)) {
            token = alice.getDelegationToken("bob", 0);
        }
        writeJaasFile(
            Base64.getEncoder().encodeToString(token.getIdentifier()),
            Base64.getEncoder().encodeToString(token.getPassword()));

        // the replicated store authenticates the token on every member;
        // retry per server since commit propagation to a follower is async
        for (int port : ports) {
            authenticateWithRetry("127.0.0.1:" + port);
        }

        try (ZooKeeper bob = client("ClientBob", "127.0.0.1:" + followerPort)) {
            bob.cancelDelegationToken(token.getIdentifier());
        }

        try (ZooKeeper cancelled = client("ClientToken", "127.0.0.1:" + leaderPort)) {
            assertThrows(KeeperException.class, () ->
                cancelled.create("/dt-quorum-cancelled", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT));
        }
    }

    private void authenticateWithRetry(String hp) throws Exception {
        long deadline = System.currentTimeMillis() + 20000;
        KeeperException last = null;
        while (System.currentTimeMillis() < deadline) {
            try (ZooKeeper tokenClient = client("ClientToken", hp)) {
                String path = tokenClient.create("/dt-quorum-", null, Ids.CREATOR_ALL_ACL,
                    CreateMode.EPHEMERAL_SEQUENTIAL);
                assertEquals("alice", tokenClient.getACL(path, null).get(0).getId().getId());
                assertTrue(tokenClient.getACL(path, null).get(0).getId().getScheme().equals("sasl"));
                return;
            } catch (KeeperException e) {
                last = e;
                Thread.sleep(200);
            }
        }
        fail("token did not authenticate against " + hp + ": " + last);
    }

}
