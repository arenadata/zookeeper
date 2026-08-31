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
import java.io.File;
import java.io.FileWriter;
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
import org.apache.zookeeper.test.SaslAuthDigestTestBase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * End-to-end coverage of master key rotation: lazy key bootstrap on the first
 * issuance, rolls through the write path, authentication with rotated keys,
 * pruning of expired keys and the restricted key znode ACL. Runs without a
 * secret file: rotation is the only key source here.
 */
public class DelegationTokenKeyRotationTest extends SaslAuthDigestTestBase {

    private static final String LOGIN_MODULE = "org.apache.zookeeper.server.auth.DigestLoginModule";
    private static final String CLIENT_CONFIG_PROP = "zookeeper.sasl.clientconfig";

    private static final long MAX_LIFETIME_MS = 20_000;

    private static File jaasFile;

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        File tmpDir = createTmpDir();
        jaasFile = new File(tmpDir, "jaas.conf");
        System.setProperty("zookeeper.authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider");
        System.setProperty("java.security.auth.login.config", jaasFile.getAbsolutePath());
        writeJaasFile("-", "-");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_KEY_ROTATION_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_MAX_LIFETIME, String.valueOf(MAX_LIFETIME_MS));
        // every explicit checkKeys() pass considers the newest key stale
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_KEY_ROLL_INTERVAL, "1");
    }

    @AfterAll
    public static void tearDownAfterClass() {
        System.clearProperty("zookeeper.authProvider.1");
        System.clearProperty("java.security.auth.login.config");
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_KEY_ROTATION_ENABLED);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_MAX_LIFETIME);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_KEY_ROLL_INTERVAL);
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

    private static void installTokenClientSection(GetDelegationTokenResponse token) throws Exception {
        writeJaasFile(
            Base64.getEncoder().encodeToString(token.getIdentifier()),
            Base64.getEncoder().encodeToString(token.getPassword()));
    }

    private ZooKeeperServer server() {
        return serverFactory.getZooKeeperServer();
    }

    private DelegationTokenCleanupManager cleanupManager() {
        ZooKeeperServer zks = server();
        return new DelegationTokenCleanupManager(
            zks.getZKDatabase(), zks.firstProcessor, zks.getDelegationTokenManager(), 3600000);
    }

    private DataNode keyNode(int keyId) {
        return server().getZKDatabase().getDataTree().getNode(DelegationTokenStore.keyPathOf(keyId));
    }

    private DataNode waitForKeyNode(int keyId, boolean present) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5000;
        DataNode node = keyNode(keyId);
        while ((present ? node == null : node != null) && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
            node = keyNode(keyId);
        }
        return node;
    }

    private void assertTokenAuthenticates(GetDelegationTokenResponse token, String owner) throws Exception {
        installTokenClientSection(token);
        try (ZooKeeper tokenClient = client("ClientToken")) {
            List<ClientInfo> clientInfo = tokenClient.whoAmI();
            assertTrue(clientInfo.stream().anyMatch(
                info -> "sasl".equals(info.getAuthScheme()) && owner.equals(info.getUser())));
        }
    }

    @Test
    public void testFirstIssuanceBootstrapsKey() throws Exception {
        GetDelegationTokenResponse token;
        try (ZooKeeper alice = client(null)) {
            token = alice.getDelegationToken("", 0);
        }
        DelegationTokenIdentifier ident = DelegationTokenIdentifier.fromBytes(token.getIdentifier());
        assertEquals(DelegationTokenSecretManager.FIRST_GENERATED_KEY_ID, ident.getMasterKeyId());
        assertNotNull(waitForKeyNode(ident.getMasterKeyId(), true), "bootstrap key znode must exist");

        assertTokenAuthenticates(token, "alice");
    }

    @Test
    public void testRollCreatesNewKeyAndOldTokensKeepWorking() throws Exception {
        GetDelegationTokenResponse oldToken;
        try (ZooKeeper alice = client(null)) {
            oldToken = alice.getDelegationToken("", 0);
        }
        int oldKeyId = DelegationTokenIdentifier.fromBytes(oldToken.getIdentifier()).getMasterKeyId();

        cleanupManager().checkKeys();
        assertNotNull(waitForKeyNode(oldKeyId + 1, true), "roll must create the next key znode");

        GetDelegationTokenResponse newToken;
        try (ZooKeeper alice = client(null)) {
            newToken = alice.getDelegationToken("", 0);
        }
        // with a 1 ms roll interval the rolled key rarely covers the new
        // token's lifetime, so issuance may mint yet another key — the old
        // key must no longer sign either way
        assertTrue(DelegationTokenIdentifier.fromBytes(newToken.getIdentifier()).getMasterKeyId() > oldKeyId,
            "new token must be signed by a newer key than the rolled-away one");

        assertTokenAuthenticates(oldToken, "alice");
        assertTokenAuthenticates(newToken, "alice");
    }

    @Test
    public void testKeyNodesNotReadableByClients() throws Exception {
        GetDelegationTokenResponse token;
        try (ZooKeeper alice = client(null)) {
            token = alice.getDelegationToken("", 0);
            int keyId = DelegationTokenIdentifier.fromBytes(token.getIdentifier()).getMasterKeyId();
            assertNotNull(waitForKeyNode(keyId, true));
            assertThrows(KeeperException.NoAuthException.class,
                () -> alice.getData(DelegationTokenStore.keyPathOf(keyId), false, null));
            assertThrows(KeeperException.NoAuthException.class,
                () -> alice.getChildren(DelegationTokenStore.KEY_NODE, false));
        }
    }

    @Test
    public void testLateIssuanceGetsKeyCoveringItsLifetime() throws Exception {
        GetDelegationTokenResponse first;
        try (ZooKeeper alice = client(null)) {
            first = alice.getDelegationToken("", 0);
        }
        int firstKeyId = DelegationTokenIdentifier.fromBytes(first.getIdentifier()).getMasterKeyId();

        // the bootstrap key expires rollInterval (1 ms) + maxLifetime after
        // creation; a full-lifetime token requested later would outlive it,
        // so issuance must mint a fresh covering key instead of reusing it
        Thread.sleep(3000);
        GetDelegationTokenResponse late;
        try (ZooKeeper alice = client(null)) {
            late = alice.getDelegationToken("", 0);
        }
        DelegationTokenIdentifier lateIdent = DelegationTokenIdentifier.fromBytes(late.getIdentifier());
        assertEquals(firstKeyId + 1, lateIdent.getMasterKeyId(),
            "token outliving the current key must be signed by a fresh key");
        assertNotNull(waitForKeyNode(lateIdent.getMasterKeyId(), true));

        assertTokenAuthenticates(first, "alice");
        assertTokenAuthenticates(late, "alice");
    }

    @Test
    public void testExpiredKeysPrunedOnRoll() throws Exception {
        try (ZooKeeper alice = client(null)) {
            alice.getDelegationToken("", 0);
        }
        DataNode keysParent = server().getZKDatabase().getDataTree().getNode(DelegationTokenStore.KEY_NODE);
        assertNotNull(keysParent);
        int bootstrapKeyId = DelegationTokenSecretManager.FIRST_GENERATED_KEY_ID;
        assertNotNull(waitForKeyNode(bootstrapKeyId, true));

        // key expiry = rollInterval (1 ms) + maxLifetime; wait it out
        long waitUntil = System.currentTimeMillis() + MAX_LIFETIME_MS + 500;
        while (System.currentTimeMillis() < waitUntil) {
            Thread.sleep(200);
        }

        cleanupManager().checkKeys();
        assertNull(waitForKeyNode(bootstrapKeyId, false), "expired key must be pruned by the roll");
        DataNode newest = server().getZKDatabase().getDataTree().getNode(
            DelegationTokenStore.keyPathOf(bootstrapKeyId + 1));
        assertNotNull(newest, "roll must still create a fresh key");
    }

}
