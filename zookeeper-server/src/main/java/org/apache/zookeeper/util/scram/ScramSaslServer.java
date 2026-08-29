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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import org.apache.zookeeper.util.scram.ScramMessages.ClientFinalMessage;
import org.apache.zookeeper.util.scram.ScramMessages.ClientFirstMessage;
import org.apache.zookeeper.util.scram.ScramMessages.ServerFinalMessage;
import org.apache.zookeeper.util.scram.ScramMessages.ServerFirstMessage;

/**
 * SCRAM-SHA-256 server per RFC 5802/7677, without channel binding or a
 * security layer. Credentials come from the standard SASL callbacks: the
 * password produced by {@link PasswordCallback} is salted per session, so the
 * same callback handler serves DIGEST-MD5 and SCRAM (including delegation
 * token validation and the token session marker).
 */
public class ScramSaslServer implements SaslServer {

    private static final int ITERATIONS = 4096;

    private enum State {
        RECEIVE_CLIENT_FIRST,
        RECEIVE_CLIENT_FINAL,
        COMPLETE,
        FAILED
    }

    private final CallbackHandler callbackHandler;

    private State state = State.RECEIVE_CLIENT_FIRST;
    private String username;
    private String authorizationIdFromClient;
    private String gs2Header;
    private byte[] storedKey;
    private byte[] serverKey;
    private String clientFirstBare;
    private ServerFirstMessage serverFirstMessage;
    private String authorizationId;

    public ScramSaslServer(CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    @Override
    public String getMechanismName() {
        return ScramFormatter.MECHANISM;
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        try {
            switch (state) {
            case RECEIVE_CLIENT_FIRST:
                return handleClientFirst(response);
            case RECEIVE_CLIENT_FINAL:
                return handleClientFinal(response);
            default:
                throw new SaslException("unexpected response in state " + state);
            }
        } catch (SaslException e) {
            state = State.FAILED;
            throw e;
        }
    }

    private byte[] handleClientFirst(byte[] response) throws SaslException {
        ClientFirstMessage clientFirst = new ClientFirstMessage(response);
        username = ScramFormatter.username(clientFirst.saslName());
        authorizationIdFromClient = clientFirst.authorizationId();
        gs2Header = clientFirst.gs2Header();
        clientFirstBare = clientFirst.clientFirstBare();

        char[] password = passwordFor(username);
        byte[] salt = ScramFormatter.secureRandomSalt();
        byte[] saltedPassword;
        try {
            saltedPassword = ScramFormatter.hi(password, salt, ITERATIONS);
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
        storedKey = ScramFormatter.storedKey(ScramFormatter.clientKey(saltedPassword));
        serverKey = ScramFormatter.serverKey(saltedPassword);

        String nonce = clientFirst.nonce() + ScramFormatter.secureRandomNonce();
        serverFirstMessage = new ServerFirstMessage(nonce, salt, ITERATIONS);
        state = State.RECEIVE_CLIENT_FINAL;
        return serverFirstMessage.toBytes();
    }

    private byte[] handleClientFinal(byte[] response) throws SaslException {
        ClientFinalMessage clientFinal = new ClientFinalMessage(response);
        String expectedChannelBinding =
            Base64.getEncoder().encodeToString(gs2Header.getBytes(StandardCharsets.UTF_8));
        if (!expectedChannelBinding.equals(clientFinal.channelBinding())) {
            throw new SaslException("channel binding does not match the gs2 header");
        }
        if (!serverFirstMessage.nonce().equals(clientFinal.nonce())) {
            throw new SaslException("nonce mismatch");
        }

        byte[] authMessage = ScramFormatter
            .authMessage(clientFirstBare, serverFirstMessage.message(), clientFinal.withoutProof())
            .getBytes(StandardCharsets.UTF_8);
        byte[] clientSignature = ScramFormatter.hmac(storedKey, authMessage);
        byte[] recoveredClientKey = ScramFormatter.xor(clientSignature, clientFinal.proof());
        if (!MessageDigest.isEqual(storedKey, ScramFormatter.storedKey(recoveredClientKey))) {
            throw new SaslException("SCRAM client proof verification failed");
        }

        String requestedAuthzid =
            authorizationIdFromClient.isEmpty() ? username : authorizationIdFromClient;
        AuthorizeCallback ac = new AuthorizeCallback(username, requestedAuthzid);
        handle(new Callback[]{ac});
        if (!ac.isAuthorized()) {
            throw new SaslException(username + " is not authorized to act as " + requestedAuthzid);
        }
        authorizationId = ac.getAuthorizedID();

        state = State.COMPLETE;
        return new ServerFinalMessage(ScramFormatter.hmac(serverKey, authMessage)).toBytes();
    }

    /**
     * Resolves the user's password through the shared callback handler; an
     * unknown user (no password set) fails authentication.
     */
    private char[] passwordFor(String username) throws SaslException {
        NameCallback nameCallback = new NameCallback("username", username);
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        handle(new Callback[]{nameCallback, passwordCallback});
        char[] password = passwordCallback.getPassword();
        passwordCallback.clearPassword();
        if (password == null) {
            throw new SaslException("authentication failed for " + username);
        }
        return password;
    }

    private void handle(Callback[] callbacks) throws SaslException {
        try {
            callbackHandler.handle(callbacks);
        } catch (SaslException e) {
            throw e;
        } catch (Exception e) {
            throw new SaslException("SCRAM callback handling failed", e);
        }
    }

    @Override
    public boolean isComplete() {
        return state == State.COMPLETE;
    }

    @Override
    public String getAuthorizationID() {
        if (!isComplete()) {
            throw new IllegalStateException("authentication is not complete");
        }
        return authorizationId;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
        throw new IllegalStateException("SCRAM negotiates no security layer");
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
        throw new IllegalStateException("SCRAM negotiates no security layer");
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (!isComplete()) {
            throw new IllegalStateException("authentication is not complete");
        }
        return Sasl.QOP.equals(propName) ? "auth" : null;
    }

    @Override
    public void dispose() {
    }

}
