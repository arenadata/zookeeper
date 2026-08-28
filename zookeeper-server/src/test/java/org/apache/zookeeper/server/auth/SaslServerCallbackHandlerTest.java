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
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import org.apache.zookeeper.server.token.DelegationTokenIdentifier;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.junit.jupiter.api.Test;

public class SaslServerCallbackHandlerTest {

    private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private static final Map<String, String> CREDENTIALS = Collections.singletonMap("bob", "bobsecret");

    private final DelegationTokenSecretManager tokenManager = new DelegationTokenSecretManager(KEY);

    private static DelegationTokenIdentifier liveToken(String owner) {
        long now = System.currentTimeMillis();
        return new DelegationTokenIdentifier(owner, "yarn", "", now, now + 3_600_000L, 1, 1);
    }

    private static char[] runNameAndPassword(SaslServerCallbackHandler handler, String username)
        throws UnsupportedCallbackException {
        NameCallback nc = new NameCallback("User:", username);
        PasswordCallback pc = new PasswordCallback("Password:", false);
        handler.handle(new Callback[]{nc, pc});
        return pc.getPassword();
    }

    @Test
    public void testTokenAuthentication() throws Exception {
        SaslServerCallbackHandler handler = new SaslServerCallbackHandler(CREDENTIALS, tokenManager);
        DelegationTokenIdentifier ident = liveToken("alice@EXAMPLE.COM");
        String username = Base64.getEncoder().encodeToString(ident.toBytes());

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
    public void testExpiredTokenRejected() throws Exception {
        SaslServerCallbackHandler handler = new SaslServerCallbackHandler(CREDENTIALS, tokenManager);
        long now = System.currentTimeMillis();
        DelegationTokenIdentifier expired =
            new DelegationTokenIdentifier("alice", "yarn", "", now - 7_200_000L, now - 3_600_000L, 1, 1);
        String username = Base64.getEncoder().encodeToString(expired.toBytes());
        assertNull(runNameAndPassword(handler, username));
    }

    @Test
    public void testStaticUserStillWorksWithTokenManager() throws Exception {
        SaslServerCallbackHandler handler = new SaslServerCallbackHandler(CREDENTIALS, tokenManager);
        assertArrayEquals("bobsecret".toCharArray(), runNameAndPassword(handler, "bob"));
    }

    @Test
    public void testUnknownUserGetsNoPassword() throws Exception {
        SaslServerCallbackHandler handler = new SaslServerCallbackHandler(CREDENTIALS, tokenManager);
        assertNull(runNameAndPassword(handler, "mallory"));
        assertNull(runNameAndPassword(handler, "bm90LWEtdG9rZW4="));
    }

    @Test
    public void testTokenLookingNameWithoutManagerIsStaticUser() throws Exception {
        DelegationTokenIdentifier ident = liveToken("alice");
        String username = Base64.getEncoder().encodeToString(ident.toBytes());
        SaslServerCallbackHandler handler = new SaslServerCallbackHandler(CREDENTIALS);
        assertNull(runNameAndPassword(handler, username));
    }

}
