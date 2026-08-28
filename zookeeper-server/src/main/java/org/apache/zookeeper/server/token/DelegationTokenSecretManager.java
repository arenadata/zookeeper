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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslException;
import org.apache.zookeeper.common.Time;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Computes and validates delegation token credentials from a static master key.
 *
 * <p>The token password is never stored: any ensemble member derives it as
 * HMAC-SHA256(masterKey, identifierBytes). The master key is shared by the whole
 * ensemble and read from the file named by {@code zookeeper.tokenAuth.secretFile}
 * (in zoo.cfg: {@code tokenAuth.secretFile}); rotation requires a config change
 * and a rolling restart.
 *
 * <p>Validation here covers only the identifier lifetime ({@code maxDate}).
 * Revocation checks arrive with the token store.
 */
public class DelegationTokenSecretManager {

    public static final String TOKEN_AUTH_ENABLED = "zookeeper.tokenAuth.enabled";
    public static final String TOKEN_AUTH_SECRET_FILE = "zookeeper.tokenAuth.secretFile";

    private static final Logger LOG = LoggerFactory.getLogger(DelegationTokenSecretManager.class);
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int MIN_KEY_LENGTH = 16;

    private final SecretKeySpec masterKey;

    public DelegationTokenSecretManager(byte[] masterKey) {
        if (masterKey == null || masterKey.length < MIN_KEY_LENGTH) {
            throw new IllegalArgumentException("token master key must be at least " + MIN_KEY_LENGTH + " bytes");
        }
        this.masterKey = new SecretKeySpec(masterKey, HMAC_ALGORITHM);
    }

    /**
     * Returns whether token authentication is enabled via {@code zookeeper.tokenAuth.enabled}.
     */
    public static boolean isEnabled() {
        return Boolean.getBoolean(TOKEN_AUTH_ENABLED);
    }

    /**
     * Creates a manager from system properties, or returns null when token
     * authentication is disabled.
     *
     * @throws IOException if enabled but the secret file is missing or unusable,
     *         so a misconfigured server fails at startup instead of silently
     *         rejecting tokens
     */
    public static DelegationTokenSecretManager createIfEnabled() throws IOException {
        if (!isEnabled()) {
            return null;
        }
        String secretFile = System.getProperty(TOKEN_AUTH_SECRET_FILE);
        if (secretFile == null || secretFile.isEmpty()) {
            throw new IOException(TOKEN_AUTH_ENABLED + " is set but " + TOKEN_AUTH_SECRET_FILE + " is not configured");
        }
        byte[] key = readSecretFile(secretFile);
        LOG.info("Delegation token authentication enabled, master key loaded from {}", secretFile);
        return new DelegationTokenSecretManager(key);
    }

    static byte[] readSecretFile(String path) throws IOException {
        byte[] raw = Files.readAllBytes(Paths.get(path));
        String secret = new String(raw, StandardCharsets.UTF_8).trim();
        byte[] key = secret.getBytes(StandardCharsets.UTF_8);
        if (key.length < MIN_KEY_LENGTH) {
            throw new IOException("token master key in " + path + " is shorter than " + MIN_KEY_LENGTH + " bytes");
        }
        return key;
    }

    /**
     * Derives the token password for the given serialized identifier.
     */
    public byte[] computePassword(byte[] identifierBytes) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(masterKey);
            return mac.doFinal(identifierBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(HMAC_ALGORITHM + " unavailable", e);
        }
    }

    /**
     * Checks that the token is still within its lifetime.
     *
     * @throws SaslException if the token has expired
     */
    public void validate(DelegationTokenIdentifier ident) throws SaslException {
        long now = Time.currentWallTime();
        if (now > ident.getMaxDate()) {
            throw new SaslException("delegation token for " + ident.getOwner()
                + " expired at " + ident.getMaxDate() + " (now " + now + ")");
        }
    }

}
