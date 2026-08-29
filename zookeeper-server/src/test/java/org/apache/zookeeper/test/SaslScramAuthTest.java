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
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.List;
import javax.security.auth.login.Configuration;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooDefs.Ids;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.client.ZKClientConfig;
import org.apache.zookeeper.common.X509Util;
import org.apache.zookeeper.data.ClientInfo;
import org.apache.zookeeper.proto.GetDelegationTokenResponse;
import org.apache.zookeeper.server.token.DelegationTokenIdentifier;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.apache.zookeeper.server.token.DelegationTokenStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * SCRAM-SHA-256 client auth end to end, with FIPS mode left ON: static JAAS
 * users and delegation tokens authenticate without DIGEST-MD5, which is the
 * point of the mechanism.
 */
public class SaslScramAuthTest extends ClientBase {

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
        System.setProperty(ZKClientConfig.ZK_SASL_CLIENT_MECHANISM, "SCRAM-SHA-256");
        // SCRAM must work with FIPS mode on; DIGEST-MD5 clients would be refused
        System.setProperty(X509Util.FIPS_MODE_PROPERTY, "true");
    }

    @AfterAll
    public static void tearDownAfterClass() {
        System.clearProperty("zookeeper.authProvider.1");
        System.clearProperty("java.security.auth.login.config");
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE);
        System.clearProperty(ZKClientConfig.ZK_SASL_CLIENT_MECHANISM);
        System.clearProperty(X509Util.FIPS_MODE_PROPERTY);
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
                + "    user_alice=\"alicepass\";\n"
                + "};\n"
                + "Client {\n"
                + "    " + LOGIN_MODULE + " required\n"
                + "    username=\"alice\"\n"
                + "    password=\"alicepass\";\n"
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

    @Test
    public void testStaticUserOverScramWithFipsOn() throws Exception {
        try (ZooKeeper alice = client(null)) {
            alice.create("/scram-static", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
            assertEquals("alice", alice.getACL("/scram-static", null).get(0).getId().getId());
            List<ClientInfo> clientInfo = alice.whoAmI();
            assertTrue(clientInfo.stream().anyMatch(
                info -> "sasl".equals(info.getAuthScheme()) && "alice".equals(info.getUser())));
        }
    }

    @Test
    public void testDelegationTokenOverScramWithFipsOn() throws Exception {
        GetDelegationTokenResponse token;
        try (ZooKeeper alice = client(null)) {
            token = alice.getDelegationToken("", 0);
        }
        assertEquals("alice", DelegationTokenIdentifier.fromBytes(token.getIdentifier()).getOwner());

        writeJaasFile(
            Base64.getEncoder().encodeToString(token.getIdentifier()),
            Base64.getEncoder().encodeToString(token.getPassword()));

        try (ZooKeeper tokenClient = client("ClientToken")) {
            tokenClient.create("/scram-token", null, Ids.CREATOR_ALL_ACL, CreateMode.PERSISTENT);
            assertEquals("alice", tokenClient.getACL("/scram-token", null).get(0).getId().getId());

            List<ClientInfo> clientInfo = tokenClient.whoAmI();
            assertTrue(clientInfo.stream().anyMatch(
                info -> "sasl".equals(info.getAuthScheme()) && "alice".equals(info.getUser())));
            assertTrue(clientInfo.stream().anyMatch(
                info -> DelegationTokenStore.TOKEN_AUTH_SCHEME.equals(info.getAuthScheme())),
                "token-authenticated session must carry the token auth marker");

            // the token session marker survives the mechanism switch
            assertThrows(KeeperException.NoAuthException.class,
                () -> tokenClient.getDelegationToken("", 0));
        }
    }

}
