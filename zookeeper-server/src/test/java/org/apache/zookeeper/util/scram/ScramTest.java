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

package org.apache.zookeeper.util.scram;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import org.apache.zookeeper.server.auth.SaslServerCallbackHandler;
import org.apache.zookeeper.server.token.DelegationTokenIdentifier;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.apache.zookeeper.server.token.DelegationTokenStore;
import org.junit.jupiter.api.Test;

public class ScramTest {

    // RFC 7677 section 3 example exchange: user "user", password "pencil"
    private static final String RFC_CLIENT_NONCE = "rOprNGfwEbeRWgbNEkqO";
    private static final String RFC_SERVER_NONCE = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    private static final byte[] RFC_SALT = Base64.getDecoder().decode("W22ZaJ0SNY7soEsUEjb6gQ==");
    private static final int RFC_ITERATIONS = 4096;
    private static final String RFC_CLIENT_FIRST = "n,,n=user,r=" + RFC_CLIENT_NONCE;
    private static final String RFC_SERVER_FIRST =
        "r=" + RFC_SERVER_NONCE + ",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    private static final String RFC_CLIENT_FINAL_WITHOUT_PROOF = "c=biws,r=" + RFC_SERVER_NONCE;
    private static final String RFC_CLIENT_PROOF = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    private static final String RFC_SERVER_SIGNATURE = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    @Test
    public void testRfc7677ClientProofAndServerSignature() throws Exception {
        byte[] saltedPassword = ScramFormatter.hi("pencil".toCharArray(), RFC_SALT, RFC_ITERATIONS);
        byte[] clientKey = ScramFormatter.clientKey(saltedPassword);
        byte[] storedKey = ScramFormatter.storedKey(clientKey);
        byte[] authMessage = ScramFormatter
            .authMessage("n=user,r=" + RFC_CLIENT_NONCE, RFC_SERVER_FIRST, RFC_CLIENT_FINAL_WITHOUT_PROOF)
            .getBytes(StandardCharsets.UTF_8);

        byte[] clientSignature = ScramFormatter.hmac(storedKey, authMessage);
        byte[] proof = ScramFormatter.xor(clientKey, clientSignature);
        assertEquals(RFC_CLIENT_PROOF, Base64.getEncoder().encodeToString(proof));

        byte[] serverKey = ScramFormatter.serverKey(saltedPassword);
        byte[] serverSignature = ScramFormatter.hmac(serverKey, authMessage);
        assertEquals(RFC_SERVER_SIGNATURE, Base64.getEncoder().encodeToString(serverSignature));
    }

    @Test
    public void testRfc7677MessagesParse() throws Exception {
        ScramMessages.ClientFirstMessage clientFirst =
            new ScramMessages.ClientFirstMessage(RFC_CLIENT_FIRST.getBytes(StandardCharsets.UTF_8));
        assertEquals("user", ScramFormatter.username(clientFirst.saslName()));
        assertEquals(RFC_CLIENT_NONCE, clientFirst.nonce());
        assertEquals("n,,", clientFirst.gs2Header());
        assertEquals("n=user,r=" + RFC_CLIENT_NONCE, clientFirst.clientFirstBare());

        ScramMessages.ServerFirstMessage serverFirst =
            new ScramMessages.ServerFirstMessage(RFC_SERVER_FIRST.getBytes(StandardCharsets.UTF_8));
        assertEquals(RFC_SERVER_NONCE, serverFirst.nonce());
        assertArrayEquals(RFC_SALT, serverFirst.salt());
        assertEquals(RFC_ITERATIONS, serverFirst.iterations());

        String clientFinalText = RFC_CLIENT_FINAL_WITHOUT_PROOF + ",p=" + RFC_CLIENT_PROOF;
        ScramMessages.ClientFinalMessage clientFinal =
            new ScramMessages.ClientFinalMessage(clientFinalText.getBytes(StandardCharsets.UTF_8));
        assertEquals("biws", clientFinal.channelBinding());
        assertEquals(RFC_SERVER_NONCE, clientFinal.nonce());
        assertEquals(RFC_CLIENT_PROOF, Base64.getEncoder().encodeToString(clientFinal.proof()));
        assertEquals(RFC_CLIENT_FINAL_WITHOUT_PROOF, clientFinal.withoutProof());

        ScramMessages.ServerFinalMessage serverFinal = ScramMessages.ServerFinalMessage.parse(
            ("v=" + RFC_SERVER_SIGNATURE).getBytes(StandardCharsets.UTF_8));
        assertNull(serverFinal.error());
        assertEquals(RFC_SERVER_SIGNATURE, Base64.getEncoder().encodeToString(serverFinal.serverSignature()));
    }

    @Test
    public void testMalformedMessagesRejected() {
        assertThrows(SaslException.class,
            () -> new ScramMessages.ClientFirstMessage("p=tls-unique,,n=user,r=abc".getBytes(StandardCharsets.UTF_8)));
        assertThrows(SaslException.class,
            () -> new ScramMessages.ClientFirstMessage("n,,m=ext,n=user,r=abc".getBytes(StandardCharsets.UTF_8)));
        assertThrows(SaslException.class,
            () -> new ScramMessages.ClientFirstMessage("garbage".getBytes(StandardCharsets.UTF_8)));
        assertThrows(SaslException.class,
            () -> new ScramMessages.ServerFirstMessage("r=abc,s=!!,i=4096".getBytes(StandardCharsets.UTF_8)));
        assertThrows(SaslException.class,
            () -> new ScramMessages.ServerFirstMessage("r=abc,s=c2FsdA==,i=0".getBytes(StandardCharsets.UTF_8)));
        assertThrows(SaslException.class,
            () -> new ScramMessages.ClientFinalMessage("c=biws,r=abc".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testSaslNameEscaping() throws Exception {
        assertEquals("a=3Db=2Cc", ScramFormatter.saslName("a=b,c"));
        assertEquals("a=b,c", ScramFormatter.username("a=3Db=2Cc"));
        assertThrows(SaslException.class, () -> ScramFormatter.username("bad=body"));
        assertThrows(SaslException.class, () -> ScramFormatter.username("trailing="));
        // base64 padding survives the round trip
        String base64 = "AbC0+/dGh=";
        assertEquals(base64, ScramFormatter.username(ScramFormatter.saslName(base64)));
    }

    private static CallbackHandler staticUserHandler(Map<String, String> users) {
        return callbacks -> {
            String username = null;
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    username = ((NameCallback) callback).getDefaultName();
                } else if (callback instanceof PasswordCallback) {
                    String password = users.get(username);
                    if (password != null) {
                        ((PasswordCallback) callback).setPassword(password.toCharArray());
                    }
                } else if (callback instanceof AuthorizeCallback) {
                    AuthorizeCallback ac = (AuthorizeCallback) callback;
                    ac.setAuthorized(true);
                    ac.setAuthorizedID(ac.getAuthorizationID());
                }
            }
        };
    }

    private static byte[] runHandshake(ScramSaslClient client, ScramSaslServer server) throws Exception {
        byte[] clientFirst = client.evaluateChallenge(new byte[0]);
        byte[] serverFirst = server.evaluateResponse(clientFirst);
        byte[] clientFinal = client.evaluateChallenge(serverFirst);
        byte[] serverFinal = server.evaluateResponse(clientFinal);
        assertNull(client.evaluateChallenge(serverFinal));
        return serverFinal;
    }

    @Test
    public void testFullHandshake() throws Exception {
        ScramSaslClient client = new ScramSaslClient("user", "pencil".toCharArray());
        ScramSaslServer server =
            new ScramSaslServer(staticUserHandler(Collections.singletonMap("user", "pencil")));
        runHandshake(client, server);
        assertTrue(client.isComplete());
        assertTrue(server.isComplete());
        assertEquals("user", server.getAuthorizationID());
        assertEquals("auth", server.getNegotiatedProperty(javax.security.sasl.Sasl.QOP));
    }

    @Test
    public void testWrongPasswordRejected() throws Exception {
        ScramSaslClient client = new ScramSaslClient("user", "wrong".toCharArray());
        ScramSaslServer server =
            new ScramSaslServer(staticUserHandler(Collections.singletonMap("user", "pencil")));
        byte[] serverFirst = server.evaluateResponse(client.evaluateChallenge(new byte[0]));
        byte[] clientFinal = client.evaluateChallenge(serverFirst);
        assertThrows(SaslException.class, () -> server.evaluateResponse(clientFinal));
    }

    @Test
    public void testUnknownUserRejectedOnlyAtProof() throws Exception {
        ScramSaslClient client = new ScramSaslClient("mallory", "pencil".toCharArray());
        ScramSaslServer server =
            new ScramSaslServer(staticUserHandler(Collections.singletonMap("user", "pencil")));
        byte[] clientFirst = client.evaluateChallenge(new byte[0]);
        // an unknown user still receives a full challenge (no enumeration oracle)
        byte[] serverFirst = server.evaluateResponse(clientFirst);
        byte[] clientFinal = client.evaluateChallenge(serverFirst);
        assertThrows(SaslException.class, () -> server.evaluateResponse(clientFinal));
    }

    @Test
    public void testClientRejectsDowngradedServerFirst() throws Exception {
        // MITM lowering the iteration count or shrinking the salt must be refused
        ScramSaslClient lowIterations = new ScramSaslClient("user", "pencil".toCharArray(), "cnonce");
        lowIterations.evaluateChallenge(new byte[0]);
        byte[] downgraded = ("r=cnonceXX,s=" + Base64.getEncoder().encodeToString(new byte[16]) + ",i=1")
            .getBytes(StandardCharsets.UTF_8);
        assertThrows(SaslException.class, () -> lowIterations.evaluateChallenge(downgraded));

        ScramSaslClient shortSalt = new ScramSaslClient("user", "pencil".toCharArray(), "cnonce");
        shortSalt.evaluateChallenge(new byte[0]);
        byte[] tinySalt = ("r=cnonceXX,s=" + Base64.getEncoder().encodeToString(new byte[1]) + ",i=4096")
            .getBytes(StandardCharsets.UTF_8);
        assertThrows(SaslException.class, () -> shortSalt.evaluateChallenge(tinySalt));
    }

    @Test
    public void testHandshakeWithTokenCallbackHandler() throws Exception {
        byte[] masterKey = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        DelegationTokenSecretManager tokenManager = new DelegationTokenSecretManager(masterKey);
        long now = System.currentTimeMillis();
        DelegationTokenIdentifier ident =
            new DelegationTokenIdentifier("alice@EXAMPLE.COM", "yarn", "", now, now + 3_600_000L, 1, 1);
        Map<Integer, byte[]> store = new HashMap<>();
        store.put(ident.getSequenceNumber(),
            DelegationTokenStore.encodeEntry(now + 3_600_000L, ident.toBytes()));
        SaslServerCallbackHandler handler = new SaslServerCallbackHandler(
            Collections.emptyMap(), tokenManager, store::get, id -> null);

        // token credentials: username = base64(identifier), password = base64(HMAC)
        String username = Base64.getEncoder().encodeToString(ident.toBytes());
        char[] password = Base64.getEncoder()
            .encodeToString(tokenManager.computePassword(ident.toBytes())).toCharArray();

        ScramSaslClient client = new ScramSaslClient(username, password);
        ScramSaslServer server = new ScramSaslServer(handler);
        runHandshake(client, server);
        assertTrue(server.isComplete());
        assertEquals("alice@EXAMPLE.COM", server.getAuthorizationID());
        assertTrue(handler.isTokenAuthenticated());
    }

}
