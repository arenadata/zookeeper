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
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import org.apache.zookeeper.util.scram.ScramMessages.ClientFinalMessage;
import org.apache.zookeeper.util.scram.ScramMessages.ClientFirstMessage;
import org.apache.zookeeper.util.scram.ScramMessages.ServerFinalMessage;
import org.apache.zookeeper.util.scram.ScramMessages.ServerFirstMessage;

/**
 * SCRAM-SHA-256 client per RFC 5802/7677, without channel binding or a
 * security layer. Constructed directly (no SASL provider registration).
 */
public class ScramSaslClient implements SaslClient {

    private static final int MIN_ITERATIONS = 4096;
    private static final int MIN_SALT_LENGTH = 8;

    private enum State {
        SEND_CLIENT_FIRST,
        RECEIVE_SERVER_FIRST,
        RECEIVE_SERVER_FINAL,
        COMPLETE,
        FAILED
    }

    private final String username;
    private final char[] password;
    private final String clientNonce;

    private State state = State.SEND_CLIENT_FIRST;
    private ClientFirstMessage clientFirstMessage;
    private byte[] saltedPassword;
    private String authMessage;

    public ScramSaslClient(String username, char[] password) {
        this(username, password, ScramFormatter.secureRandomNonce());
    }

    // VisibleForTesting: fixed nonce
    ScramSaslClient(String username, char[] password, String clientNonce) {
        this.username = username;
        this.password = password.clone();
        this.clientNonce = clientNonce;
    }

    @Override
    public String getMechanismName() {
        return ScramFormatter.MECHANISM;
    }

    @Override
    public boolean hasInitialResponse() {
        return true;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        try {
            switch (state) {
            case SEND_CLIENT_FIRST:
                clientFirstMessage = new ClientFirstMessage(ScramFormatter.saslName(username), clientNonce);
                state = State.RECEIVE_SERVER_FIRST;
                return clientFirstMessage.toBytes();
            case RECEIVE_SERVER_FIRST:
                ServerFirstMessage serverFirst = new ServerFirstMessage(challenge);
                if (!serverFirst.nonce().startsWith(clientNonce)) {
                    throw new SaslException("server nonce does not extend the client nonce");
                }
                // RFC 7677 floor: a MITM lowering the count or shrinking the
                // salt would make the transmitted proof cheap to attack offline
                if (serverFirst.iterations() < MIN_ITERATIONS) {
                    throw new SaslException("server iteration count " + serverFirst.iterations()
                        + " is below the minimum " + MIN_ITERATIONS);
                }
                if (serverFirst.salt().length < MIN_SALT_LENGTH) {
                    throw new SaslException("server salt is shorter than " + MIN_SALT_LENGTH + " bytes");
                }
                saltedPassword = ScramFormatter.hi(password, serverFirst.salt(), serverFirst.iterations());
                byte[] clientKey = ScramFormatter.clientKey(saltedPassword);
                byte[] storedKey = ScramFormatter.storedKey(clientKey);
                ClientFinalMessage clientFinal =
                    new ClientFinalMessage(clientFirstMessage.gs2Header(), serverFirst.nonce(), new byte[0]);
                authMessage = ScramFormatter.authMessage(
                    clientFirstMessage.clientFirstBare(), serverFirst.message(), clientFinal.withoutProof());
                byte[] clientSignature =
                    ScramFormatter.hmac(storedKey, authMessage.getBytes(StandardCharsets.UTF_8));
                byte[] proof = ScramFormatter.xor(clientKey, clientSignature);
                state = State.RECEIVE_SERVER_FINAL;
                return new ClientFinalMessage(clientFirstMessage.gs2Header(), serverFirst.nonce(), proof).toBytes();
            case RECEIVE_SERVER_FINAL:
                ServerFinalMessage serverFinal = ServerFinalMessage.parse(challenge);
                if (serverFinal.error() != null) {
                    throw new SaslException("SCRAM authentication failed: " + serverFinal.error());
                }
                byte[] serverKey = ScramFormatter.serverKey(saltedPassword);
                byte[] expectedSignature =
                    ScramFormatter.hmac(serverKey, authMessage.getBytes(StandardCharsets.UTF_8));
                if (!MessageDigest.isEqual(expectedSignature, serverFinal.serverSignature())) {
                    throw new SaslException("invalid server signature");
                }
                state = State.COMPLETE;
                return null;
            default:
                throw new SaslException("unexpected challenge in state " + state);
            }
        } catch (SaslException e) {
            state = State.FAILED;
            throw e;
        }
    }

    @Override
    public boolean isComplete() {
        return state == State.COMPLETE;
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
        java.util.Arrays.fill(password, '\0');
    }

}
