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
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslException;

/**
 * SCRAM-SHA-256 primitives per RFC 5802/7677: Hi (PBKDF2), the key/signature
 * derivations and the saslname escaping. Only FIPS-approved algorithms are
 * involved (SHA-256, HMAC-SHA-256, PBKDF2).
 */
public final class ScramFormatter {

    public static final String MECHANISM = "SCRAM-SHA-256";

    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_LENGTH_BITS = 256;

    private static final byte[] CLIENT_KEY_LABEL = "Client Key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SERVER_KEY_LABEL = "Server Key".getBytes(StandardCharsets.UTF_8);

    private static final SecureRandom RANDOM = new SecureRandom();

    private ScramFormatter() {
    }

    public static byte[] h(byte[] data) throws SaslException {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new SaslException(HASH_ALGORITHM + " unavailable", e);
        }
    }

    public static byte[] hmac(byte[] key, byte[] data) throws SaslException {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new SaslException(HMAC_ALGORITHM + " failure", e);
        }
    }

    /**
     * Hi(str, salt, i) from RFC 5802, which is PBKDF2-HMAC-SHA-256.
     */
    public static byte[] hi(char[] password, byte[] salt, int iterations) throws SaslException {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH_BITS);
            try {
                return SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM).generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new SaslException(KEY_DERIVATION_ALGORITHM + " failure", e);
        }
    }

    public static byte[] clientKey(byte[] saltedPassword) throws SaslException {
        return hmac(saltedPassword, CLIENT_KEY_LABEL);
    }

    public static byte[] serverKey(byte[] saltedPassword) throws SaslException {
        return hmac(saltedPassword, SERVER_KEY_LABEL);
    }

    public static byte[] storedKey(byte[] clientKey) throws SaslException {
        return h(clientKey);
    }

    public static byte[] xor(byte[] first, byte[] second) throws SaslException {
        if (first.length != second.length) {
            throw new SaslException("argument length mismatch");
        }
        byte[] result = new byte[first.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (first[i] ^ second[i]);
        }
        return result;
    }

    public static String authMessage(String clientFirstBare, String serverFirst, String clientFinalWithoutProof) {
        return clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof;
    }

    /**
     * Escapes a username into an RFC 5802 saslname: '=' as "=3D", ',' as "=2C".
     */
    public static String saslName(String username) {
        return username.replace("=", "=3D").replace(",", "=2C");
    }

    /**
     * Reverses {@link #saslName(String)}; rejects any other use of '='.
     */
    public static String username(String saslName) throws SaslException {
        StringBuilder username = new StringBuilder(saslName.length());
        for (int i = 0; i < saslName.length(); i++) {
            char c = saslName.charAt(i);
            if (c != '=') {
                username.append(c);
                continue;
            }
            if (i + 2 >= saslName.length()) {
                throw new SaslException("invalid saslname escaping");
            }
            String escape = saslName.substring(i + 1, i + 3);
            if ("3D".equals(escape)) {
                username.append('=');
            } else if ("2C".equals(escape)) {
                username.append(',');
            } else {
                throw new SaslException("invalid saslname escaping");
            }
            i += 2;
        }
        return username.toString();
    }

    public static String secureRandomNonce() {
        byte[] bytes = new byte[18];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] secureRandomSalt() {
        byte[] salt = new byte[24];
        RANDOM.nextBytes(salt);
        return salt;
    }

}
