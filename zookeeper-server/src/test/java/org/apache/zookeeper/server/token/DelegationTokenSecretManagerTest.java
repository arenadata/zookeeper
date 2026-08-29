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

package org.apache.zookeeper.server.token;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class DelegationTokenSecretManagerTest {

    private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path tmpDir;

    @AfterEach
    public void clearProperties() {
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_KEY_ROTATION_ENABLED);
    }

    @Test
    public void testComputePasswordDeterministicAndKeySensitive() {
        DelegationTokenSecretManager manager = new DelegationTokenSecretManager(KEY);
        byte[] identifier = new DelegationTokenIdentifier("alice", "yarn", "", 1L, 2L, 3, 4).toBytes();
        assertArrayEquals(manager.computePassword(identifier), manager.computePassword(identifier));
        assertEquals(32, manager.computePassword(identifier).length);

        byte[] otherIdentifier = new DelegationTokenIdentifier("bob", "yarn", "", 1L, 2L, 3, 4).toBytes();
        assertFalse(Arrays.equals(manager.computePassword(identifier), manager.computePassword(otherIdentifier)));

        DelegationTokenSecretManager otherKeyManager =
            new DelegationTokenSecretManager("another-master-key-of-decent-size".getBytes(StandardCharsets.UTF_8));
        assertFalse(Arrays.equals(manager.computePassword(identifier), otherKeyManager.computePassword(identifier)));
    }

    @Test
    public void testShortKeyRejected() {
        assertThrows(IllegalArgumentException.class,
            () -> new DelegationTokenSecretManager("short".getBytes(StandardCharsets.UTF_8)));
        assertThrows(IllegalArgumentException.class, () -> new DelegationTokenSecretManager(null));
    }

    @Test
    public void testValidateLifetime() {
        DelegationTokenSecretManager manager = new DelegationTokenSecretManager(KEY);
        long now = System.currentTimeMillis();
        DelegationTokenIdentifier live =
            new DelegationTokenIdentifier("alice", "yarn", "", now, now + 3_600_000L, 1, 1);
        assertDoesNotThrow(() -> manager.validate(live));

        DelegationTokenIdentifier expired =
            new DelegationTokenIdentifier("alice", "yarn", "", now - 7_200_000L, now - 3_600_000L, 1, 1);
        assertThrows(SaslException.class, () -> manager.validate(expired));
    }

    @Test
    public void testCreateIfEnabledDisabledByDefault() throws IOException {
        assertNull(DelegationTokenSecretManager.createIfEnabled());
    }

    @Test
    public void testCreateIfEnabledWithoutSecretFileFails() {
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        assertThrows(IOException.class, DelegationTokenSecretManager::createIfEnabled);
    }

    @Test
    public void testCreateIfEnabledMissingFileFails() {
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE,
            tmpDir.resolve("absent").toString());
        assertThrows(IOException.class, DelegationTokenSecretManager::createIfEnabled);
    }

    @Test
    public void testCreateIfEnabledReadsAndTrimsSecret() throws IOException {
        Path secretFile = tmpDir.resolve("master.key");
        Files.write(secretFile, "  0123456789abcdef0123456789abcdef\n".getBytes(StandardCharsets.UTF_8));
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE, secretFile.toString());

        DelegationTokenSecretManager manager = DelegationTokenSecretManager.createIfEnabled();
        assertNotNull(manager);
        byte[] identifier = new DelegationTokenIdentifier("alice", "yarn", "", 1L, 2L, 3, 4).toBytes();
        assertArrayEquals(new DelegationTokenSecretManager(KEY).computePassword(identifier),
            manager.computePassword(identifier));
    }

    @Test
    public void testShortSecretFileFails() throws IOException {
        Path secretFile = tmpDir.resolve("weak.key");
        Files.write(secretFile, "weak\n".getBytes(StandardCharsets.UTF_8));
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE, secretFile.toString());
        assertThrows(IOException.class, DelegationTokenSecretManager::createIfEnabled);
    }

    @Test
    public void testRotationAllowsMissingSecretFile() throws IOException {
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_KEY_ROTATION_ENABLED, "true");

        DelegationTokenSecretManager manager = DelegationTokenSecretManager.createIfEnabled();
        assertNotNull(manager);
        assertTrue(manager.isKeyRotationEnabled());
        assertFalse(manager.hasStaticKey());
        assertThrows(IllegalStateException.class, () -> manager.computePassword(new byte[]{1}));
    }

    @Test
    public void testRotationKeepsStaticKeyWhenFilePresent() throws IOException {
        Path secretFile = tmpDir.resolve("master.key");
        Files.write(secretFile, KEY);
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE, secretFile.toString());
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_KEY_ROTATION_ENABLED, "true");

        DelegationTokenSecretManager manager = DelegationTokenSecretManager.createIfEnabled();
        assertNotNull(manager);
        assertTrue(manager.isKeyRotationEnabled());
        assertTrue(manager.hasStaticKey());
    }

    @Test
    public void testGeneratedKeyPasswords() {
        DelegationTokenSecretManager manager = new DelegationTokenSecretManager(null, true);
        byte[] keyA = manager.generateKeyBytes();
        byte[] keyB = manager.generateKeyBytes();
        assertEquals(32, keyA.length);
        assertFalse(Arrays.equals(keyA, keyB));

        byte[] identifier = new DelegationTokenIdentifier("alice", "yarn", "", 1L, 2L, 3, 2).toBytes();
        assertArrayEquals(DelegationTokenSecretManager.computePassword(keyA, identifier),
            DelegationTokenSecretManager.computePassword(keyA, identifier));
        assertFalse(Arrays.equals(DelegationTokenSecretManager.computePassword(keyA, identifier),
            DelegationTokenSecretManager.computePassword(keyB, identifier)));
        // static-key derivation matches the explicit-key overload for the same bytes
        assertArrayEquals(new DelegationTokenSecretManager(KEY).computePassword(identifier),
            DelegationTokenSecretManager.computePassword(KEY, identifier));
    }

    @Test
    public void testNewKeyExpiryCoversTokenLifetime() {
        DelegationTokenSecretManager manager = new DelegationTokenSecretManager(null, true);
        long now = System.currentTimeMillis();
        assertEquals(now + manager.getKeyRollIntervalMs() + manager.getMaxLifetimeMs(), manager.newKeyExpiry(now));
    }

    @Test
    public void testKeyEntryCodec() throws IOException {
        byte[] entry = DelegationTokenStore.encodeKeyEntry(11L, 22L, KEY);
        assertEquals(11L, DelegationTokenStore.keyEntryCreated(entry));
        assertEquals(22L, DelegationTokenStore.keyEntryExpiry(entry));
        assertArrayEquals(KEY, DelegationTokenStore.keyEntryBytes(entry));

        assertThrows(IOException.class, () -> DelegationTokenStore.keyEntryExpiry(null));
        assertThrows(IOException.class, () -> DelegationTokenStore.keyEntryExpiry(new byte[]{1, 2, 3}));
        byte[] wrongVersion = DelegationTokenStore.encodeKeyEntry(11L, 22L, KEY);
        wrongVersion[0] = 9;
        assertThrows(IOException.class, () -> DelegationTokenStore.keyEntryBytes(wrongVersion));
    }

}
