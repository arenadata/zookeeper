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

package org.apache.zookeeper.server.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import org.apache.zookeeper.server.token.DelegationTokenIdentifier;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.apache.zookeeper.server.token.DelegationTokenStore;
import org.junit.jupiter.api.Test;

public class SaslServerCallbackHandlerTest {

    private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private static final Map<String, String> CREDENTIALS = Collections.singletonMap("bob", "bobsecret");

    private final DelegationTokenSecretManager tokenManager = new DelegationTokenSecretManager(KEY);
    private final Map<Integer, byte[]> store = new HashMap<>();
    private final Map<Integer, byte[]> keyStore = new HashMap<>();
    private final DelegationTokenStore.EntryReader storeReader = store::get;
    private final DelegationTokenStore.KeyReader keyReader = keyStore::get;

    private SaslServerCallbackHandler handler() {
        return new SaslServerCallbackHandler(CREDENTIALS, tokenManager, storeReader, keyReader);
    }

    private static DelegationTokenIdentifier liveToken(String owner) {
        long now = System.currentTimeMillis();
        return new DelegationTokenIdentifier(owner, "yarn", "", now, now + 3_600_000L, 1, 1);
    }

    private void putInStore(DelegationTokenIdentifier ident, long expiry) {
        store.put(ident.getSequenceNumber(), DelegationTokenStore.encodeEntry(expiry, ident.toBytes()));
    }

    private static char[] runNameAndPassword(SaslServerCallbackHandler handler, String username)
        throws UnsupportedCallbackException {
        NameCallback nc = new NameCallback("User:", username);
        PasswordCallback pc = new PasswordCallback("Password:", false);
        handler.handle(new Callback[]{nc, pc});
        return pc.getPassword();
    }

    private static String tokenUsername(DelegationTokenIdentifier ident) {
        return Base64.getEncoder().encodeToString(ident.toBytes());
    }

    @Test
    public void testTokenAuthentication() throws Exception {
        SaslServerCallbackHandler handler = handler();
        DelegationTokenIdentifier ident = liveToken("alice@EXAMPLE.COM");
        putInStore(ident, System.currentTimeMillis() + 3_600_000L);
        String username = tokenUsername(ident);

        char[] password = runNameAndPassword(handler, username);
        char[] expected = Base64.getEncoder()
            .encodeToString(tokenManager.computePassword(ident.toBytes())).toCharArray();
        assertArrayEquals(expected, password);

        AuthorizeCallback ac = new AuthorizeCallback(username, username);
        handler.handle(new Callback[]{ac});
        assertTrue(ac.isAuthorized());
        assertEquals("alice@EXAMPLE.COM", ac.getAuthorizedID());
    }

    @Test
    public void testTokenNotInStoreRejected() throws Exception {
        DelegationTokenIdentifier ident = liveToken("alice");
        assertNull(runNameAndPassword(handler(), tokenUsername(ident)));
    }

    @Test
    public void testTokenPastStoreExpiryRejected() throws Exception {
        DelegationTokenIdentifier ident = liveToken("alice");
        putInStore(ident, System.currentTimeMillis() - 1000L);
        assertNull(runNameAndPassword(handler(), tokenUsername(ident)));
    }

    @Test
    public void testTokenMismatchingStoreEntryRejected() throws Exception {
        DelegationTokenIdentifier ident = liveToken("alice");
        DelegationTokenIdentifier other = new DelegationTokenIdentifier(
            "mallory", "yarn", "", ident.getIssueDate(), ident.getMaxDate(), ident.getSequenceNumber(), 1);
        putInStore(other, System.currentTimeMillis() + 3_600_000L);
        assertNull(runNameAndPassword(handler(), tokenUsername(ident)));
    }

    @Test
    public void testExpiredTokenRejected() throws Exception {
        long now = System.currentTimeMillis();
        DelegationTokenIdentifier expired =
            new DelegationTokenIdentifier("alice", "yarn", "", now - 7_200_000L, now - 3_600_000L, 1, 1);
        putInStore(expired, now + 3_600_000L);
        assertNull(runNameAndPassword(handler(), tokenUsername(expired)));
    }

    @Test
    public void testStaticUserStillWorksWithTokenManager() throws Exception {
        assertArrayEquals("bobsecret".toCharArray(), runNameAndPassword(handler(), "bob"));
    }

    @Test
    public void testUnknownUserGetsNoPassword() throws Exception {
        SaslServerCallbackHandler handler = handler();
        assertNull(runNameAndPassword(handler, "mallory"));
        assertNull(runNameAndPassword(handler, "bm90LWEtdG9rZW4="));
    }

    @Test
    public void testTokenLookingNameWithoutManagerIsStaticUser() throws Exception {
        DelegationTokenIdentifier ident = liveToken("alice");
        SaslServerCallbackHandler handler = new SaslServerCallbackHandler(CREDENTIALS);
        assertNull(runNameAndPassword(handler, tokenUsername(ident)));
    }

    private static DelegationTokenIdentifier liveRotatedToken(String owner, int keyId) {
        long now = System.currentTimeMillis();
        return new DelegationTokenIdentifier(owner, "yarn", "", now, now + 3_600_000L, 7, keyId);
    }

    private void putKeyInStore(int keyId, byte[] keyBytes, long created, long expiry) {
        keyStore.put(keyId, DelegationTokenStore.encodeKeyEntry(created, expiry, keyBytes));
    }

    @Test
    public void testRotatedKeyTokenAuthentication() throws Exception {
        SaslServerCallbackHandler handler = handler();
        long now = System.currentTimeMillis();
        byte[] rotatedKey = tokenManager.generateKeyBytes();
        putKeyInStore(2, rotatedKey, now, now + 3_600_000L);
        DelegationTokenIdentifier ident = liveRotatedToken("alice", 2);
        putInStore(ident, now + 3_600_000L);

        char[] password = runNameAndPassword(handler, tokenUsername(ident));
        char[] expected = Base64.getEncoder()
            .encodeToString(DelegationTokenSecretManager.computePassword(rotatedKey, ident.toBytes())).toCharArray();
        assertArrayEquals(expected, password);
    }

    @Test
    public void testUnknownSigningKeyRejected() throws Exception {
        DelegationTokenIdentifier ident = liveRotatedToken("alice", 5);
        putInStore(ident, System.currentTimeMillis() + 3_600_000L);
        assertNull(runNameAndPassword(handler(), tokenUsername(ident)));
    }

    @Test
    public void testExpiredSigningKeyRejected() throws Exception {
        long now = System.currentTimeMillis();
        putKeyInStore(2, tokenManager.generateKeyBytes(), now - 7_200_000L, now - 1000L);
        DelegationTokenIdentifier ident = liveRotatedToken("alice", 2);
        putInStore(ident, now + 3_600_000L);
        assertNull(runNameAndPassword(handler(), tokenUsername(ident)));
    }

    @Test
    public void testStaticKeyTokenWithoutSecretFileRejected() throws Exception {
        DelegationTokenSecretManager rotationOnly = new DelegationTokenSecretManager(null, true);
        SaslServerCallbackHandler handler =
            new SaslServerCallbackHandler(CREDENTIALS, rotationOnly, storeReader, keyReader);
        DelegationTokenIdentifier ident = liveToken("alice");
        putInStore(ident, System.currentTimeMillis() + 3_600_000L);
        assertNull(runNameAndPassword(handler, tokenUsername(ident)));
    }

}
