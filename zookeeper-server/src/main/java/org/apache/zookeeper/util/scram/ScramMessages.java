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
import java.util.Base64;
import javax.security.sasl.SaslException;

/**
 * The four SCRAM handshake messages of RFC 5802, parsed strictly. Channel
 * binding ("p=...") and mandatory extensions ("m=...") are rejected;
 * optional extensions are tolerated where the grammar allows them.
 */
public final class ScramMessages {

    private ScramMessages() {
    }

    private static String requireAttribute(String field, char attribute) throws SaslException {
        if (field.length() < 2 || field.charAt(0) != attribute || field.charAt(1) != '=') {
            throw new SaslException("expected '" + attribute + "=' attribute in SCRAM message");
        }
        return field.substring(2);
    }

    public static final class ClientFirstMessage {

        private final String saslName;
        private final String nonce;
        private final String authorizationId;
        private final String gs2Header;
        private final String clientFirstBare;

        public ClientFirstMessage(String saslName, String nonce) {
            this.saslName = saslName;
            this.nonce = nonce;
            this.authorizationId = "";
            this.gs2Header = "n,,";
            this.clientFirstBare = "n=" + saslName + ",r=" + nonce;
        }

        public ClientFirstMessage(byte[] message) throws SaslException {
            String text = new String(message, StandardCharsets.UTF_8);
            // gs2-header: cbind-flag "," [ authzid ] ","
            char cbindFlag = text.isEmpty() ? 0 : text.charAt(0);
            if (cbindFlag == 'p') {
                throw new SaslException("channel binding is not supported");
            }
            if ((cbindFlag != 'n' && cbindFlag != 'y') || text.length() < 2 || text.charAt(1) != ',') {
                throw new SaslException("malformed SCRAM gs2 header");
            }
            int headerEnd = text.indexOf(',', 2);
            if (headerEnd < 0) {
                throw new SaslException("malformed SCRAM gs2 header");
            }
            String authzidField = text.substring(2, headerEnd);
            if (authzidField.isEmpty()) {
                this.authorizationId = "";
            } else {
                this.authorizationId = ScramFormatter.username(requireAttribute(authzidField, 'a'));
            }
            this.gs2Header = text.substring(0, headerEnd + 1);
            this.clientFirstBare = text.substring(headerEnd + 1);

            String[] fields = clientFirstBare.split(",");
            if (fields.length < 2) {
                throw new SaslException("malformed SCRAM client-first message");
            }
            if (fields[0].startsWith("m=")) {
                throw new SaslException("mandatory SCRAM extensions are not supported");
            }
            this.saslName = requireAttribute(fields[0], 'n');
            this.nonce = requireAttribute(fields[1], 'r');
            if (saslName.isEmpty() || nonce.isEmpty()) {
                throw new SaslException("malformed SCRAM client-first message");
            }
        }

        public String saslName() {
            return saslName;
        }

        public String nonce() {
            return nonce;
        }

        public String authorizationId() {
            return authorizationId;
        }

        public String gs2Header() {
            return gs2Header;
        }

        public String clientFirstBare() {
            return clientFirstBare;
        }

        public byte[] toBytes() {
            return (gs2Header + clientFirstBare).getBytes(StandardCharsets.UTF_8);
        }

    }

    public static final class ServerFirstMessage {

        private final String nonce;
        private final byte[] salt;
        private final int iterations;
        private final String message;

        public ServerFirstMessage(String nonce, byte[] salt, int iterations) {
            this.nonce = nonce;
            this.salt = salt;
            this.iterations = iterations;
            this.message = "r=" + nonce + ",s=" + Base64.getEncoder().encodeToString(salt) + ",i=" + iterations;
        }

        public ServerFirstMessage(byte[] messageBytes) throws SaslException {
            this.message = new String(messageBytes, StandardCharsets.UTF_8);
            String[] fields = message.split(",");
            if (fields.length < 3) {
                throw new SaslException("malformed SCRAM server-first message");
            }
            if (fields[0].startsWith("m=")) {
                throw new SaslException("mandatory SCRAM extensions are not supported");
            }
            this.nonce = requireAttribute(fields[0], 'r');
            try {
                this.salt = Base64.getDecoder().decode(requireAttribute(fields[1], 's'));
                this.iterations = Integer.parseInt(requireAttribute(fields[2], 'i'));
            } catch (IllegalArgumentException e) {
                throw new SaslException("malformed SCRAM server-first message");
            }
            if (nonce.isEmpty() || salt.length == 0 || iterations < 1) {
                throw new SaslException("malformed SCRAM server-first message");
            }
        }

        public String nonce() {
            return nonce;
        }

        public byte[] salt() {
            return salt;
        }

        public int iterations() {
            return iterations;
        }

        public String message() {
            return message;
        }

        public byte[] toBytes() {
            return message.getBytes(StandardCharsets.UTF_8);
        }

    }

    public static final class ClientFinalMessage {

        private final String channelBinding;
        private final String nonce;
        private final byte[] proof;
        private final String withoutProof;

        public ClientFinalMessage(String gs2Header, String nonce, byte[] proof) {
            this.channelBinding = Base64.getEncoder().encodeToString(gs2Header.getBytes(StandardCharsets.UTF_8));
            this.nonce = nonce;
            this.proof = proof;
            this.withoutProof = "c=" + channelBinding + ",r=" + nonce;
        }

        public ClientFinalMessage(byte[] message) throws SaslException {
            String text = new String(message, StandardCharsets.UTF_8);
            int proofStart = text.lastIndexOf(",p=");
            if (proofStart < 0) {
                throw new SaslException("malformed SCRAM client-final message");
            }
            this.withoutProof = text.substring(0, proofStart);
            String[] fields = withoutProof.split(",");
            if (fields.length < 2) {
                throw new SaslException("malformed SCRAM client-final message");
            }
            this.channelBinding = requireAttribute(fields[0], 'c');
            this.nonce = requireAttribute(fields[1], 'r');
            try {
                this.proof = Base64.getDecoder().decode(text.substring(proofStart + 3));
            } catch (IllegalArgumentException e) {
                throw new SaslException("malformed SCRAM client-final message");
            }
            if (channelBinding.isEmpty() || nonce.isEmpty() || proof.length == 0) {
                throw new SaslException("malformed SCRAM client-final message");
            }
        }

        public String channelBinding() {
            return channelBinding;
        }

        public String nonce() {
            return nonce;
        }

        public byte[] proof() {
            return proof;
        }

        public String withoutProof() {
            return withoutProof;
        }

        public byte[] toBytes() {
            return (withoutProof + ",p=" + Base64.getEncoder().encodeToString(proof))
                .getBytes(StandardCharsets.UTF_8);
        }

    }

    public static final class ServerFinalMessage {

        private final byte[] serverSignature;
        private final String error;

        public ServerFinalMessage(byte[] serverSignature) {
            this.serverSignature = serverSignature;
            this.error = null;
        }

        private ServerFinalMessage(byte[] serverSignature, String error) {
            this.serverSignature = serverSignature;
            this.error = error;
        }

        public static ServerFinalMessage parse(byte[] message) throws SaslException {
            String text = new String(message, StandardCharsets.UTF_8);
            String field = text.split(",")[0];
            if (field.startsWith("e=")) {
                return new ServerFinalMessage(null, field.substring(2));
            }
            try {
                return new ServerFinalMessage(Base64.getDecoder().decode(requireAttribute(field, 'v')), null);
            } catch (IllegalArgumentException e) {
                throw new SaslException("malformed SCRAM server-final message");
            }
        }

        public byte[] serverSignature() {
            return serverSignature;
        }

        public String error() {
            return error;
        }

        public byte[] toBytes() {
            String text = error != null
                ? "e=" + error
                : "v=" + Base64.getEncoder().encodeToString(serverSignature);
            return text.getBytes(StandardCharsets.UTF_8);
        }

    }

}
