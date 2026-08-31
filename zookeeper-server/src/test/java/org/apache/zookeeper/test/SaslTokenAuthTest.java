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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooDefs.Ids;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.apache.zookeeper.server.token.DelegationTokenTool;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Authentication-path checks for delegation tokens: a token that is not in
 * the replicated store (e.g. minted offline with the master key) must be
 * rejected even though its HMAC is valid — this is what makes cancellation
 * effective — while static DIGEST users keep working on the same server.
 */
public class SaslTokenAuthTest extends SaslAuthDigestTestBase {

    private static final String CLIENT_SECTION_SUPER = "ClientSuper";

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        File tmpDir = createTmpDir();
        File secretFile = new File(tmpDir, "master.key");
        Files.write(secretFile.toPath(), "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));

        // an HMAC-valid token minted outside the server, absent from the store
        ByteArrayOutputStream toolOutput = new ByteArrayOutputStream();
        DelegationTokenTool.run(new String[]{
            "--secret-file", secretFile.getAbsolutePath(),
            "--owner", "alice",
            "--max-lifetime", "1h",
        }, new PrintStream(toolOutput, true, "UTF-8"));
        String identifier = toolOutputValue(toolOutput.toString("UTF-8"), "Identifier:");
        String password = toolOutputValue(toolOutput.toString("UTF-8"), "Password:");

        File jaasFile = new File(tmpDir, "jaas.conf");
        try (FileWriter writer = new FileWriter(jaasFile)) {
            writer.write(""
                + "Server {\n"
                + "    " + SaslTestUtil.digestLoginModule + " required\n"
                + "    user_super=\"test\";\n"
                + "};\n"
                + "Client {\n"
                + "    " + SaslTestUtil.digestLoginModule + " required\n"
                + "    username=\"" + identifier + "\"\n"
                + "    password=\"" + password + "\";\n"
                + "};\n"
                + CLIENT_SECTION_SUPER + " {\n"
                + "    " + SaslTestUtil.digestLoginModule + " required\n"
                + "    username=\"super\"\n"
                + "    password=\"test\";\n"
                + "};\n");
        }

        System.setProperty(SaslTestUtil.authProviderProperty, SaslTestUtil.authProvider);
        System.setProperty(SaslTestUtil.jaasConfig, jaasFile.getAbsolutePath());
        System.setProperty("zookeeper.allowSaslFailedClients", "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE, secretFile.getAbsolutePath());
    }

    @AfterAll
    public static void tearDownAfterClass() {
        System.clearProperty(SaslTestUtil.authProviderProperty);
        System.clearProperty(SaslTestUtil.jaasConfig);
        System.clearProperty("zookeeper.allowSaslFailedClients");
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE);
    }

    private static String toolOutputValue(String output, String label) {
        for (String line : output.split("\n")) {
            if (line.startsWith(label)) {
                return line.substring(label.length()).trim();
            }
        }
        throw new IllegalStateException("no '" + label + "' line in tool output:\n" + output);
    }

    @Test
    public void testOfflineTokenNotInStoreRejected() throws Exception {
        ZooKeeper zk = null;
        CountdownWatcher watcher = new CountdownWatcher();
        try {
            zk = createClient(watcher);
            // SASL failed, so the session has no sasl id and CREATOR_ALL_ACL
            // cannot be satisfied
            final ZooKeeper failedClient = zk;
            assertThrows(KeeperException.class, () ->
                failedClient.create("/offline-token-test", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT));
            // issuance also requires a successfully SASL-authenticated session
            assertThrows(KeeperException.AuthFailedException.class, () ->
                failedClient.getDelegationToken("bob", 0));
        } finally {
            if (zk != null) {
                zk.close();
            }
        }
    }

    @Test
    public void testStaticDigestUserCoexists() throws Exception {
        System.setProperty("zookeeper.sasl.clientconfig", CLIENT_SECTION_SUPER);
        ZooKeeper zk = null;
        CountdownWatcher watcher = new CountdownWatcher();
        try {
            zk = createClient(watcher);
            zk.create("/token-auth-super-test", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
            assertNotNull(zk.exists("/token-auth-super-test", false));
        } finally {
            System.clearProperty("zookeeper.sasl.clientconfig");
            if (zk != null) {
                zk.close();
            }
        }
    }

}
