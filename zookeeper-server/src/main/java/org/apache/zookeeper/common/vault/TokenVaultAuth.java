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

package org.apache.zookeeper.common.vault;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.function.Function;
import org.apache.zookeeper.common.StringUtils;

/**
 * A Vault token read from the file named by {@link VaultCredentialProvider#TOKEN_PATH}; without
 * one, from the systemd credential {@value #SYSTEMD_CREDENTIAL_NAME}, else from the
 * {@value #VAULT_TOKEN_ENV} environment variable. The token is read again at every login, so a
 * rotated token is picked up once Vault refuses the old one.
 */
final class TokenVaultAuth implements VaultAuthMethod {

    static final String VAULT_TOKEN_ENV = "VAULT_TOKEN";
    static final String CREDENTIALS_DIRECTORY_ENV = "CREDENTIALS_DIRECTORY";
    static final String SYSTEMD_CREDENTIAL_NAME = "vault-token";

    private final String tokenPath;
    private final Function<String, String> env;

    TokenVaultAuth(String tokenPath, Function<String, String> env) {
        this.tokenPath = tokenPath;
        this.env = env;
    }

    @Override
    public String authenticate(VaultHttpClient client) throws IOException {
        String token = resolveToken();
        if (token == null) {
            throw new IOException("Vault token not found: set " + VaultCredentialProvider.TOKEN_PATH
                + ", provide the systemd credential " + SYSTEMD_CREDENTIAL_NAME
                + " or set the " + VAULT_TOKEN_ENV + " environment variable");
        }
        return token;
    }

    String resolveToken() throws IOException {
        String token;
        if (tokenPath != null) {
            token = readToken(new File(tokenPath));
            if (token == null) {
                throw new IOException("Vault token file " + tokenPath + " is empty");
            }
        } else {
            token = null;
            String credentialsDirectory = env.apply(CREDENTIALS_DIRECTORY_ENV);
            if (credentialsDirectory != null && !credentialsDirectory.isEmpty()) {
                File credential = new File(credentialsDirectory, SYSTEMD_CREDENTIAL_NAME);
                if (credential.isFile()) {
                    token = readToken(credential);
                }
            }
            if (token == null) {
                token = StringUtils.trimToNull(env.apply(VAULT_TOKEN_ENV));
            }
        }
        if (token != null) {
            checkToken(token);
        }
        return token;
    }

    /**
     * Reads a token file, dropping the byte order mark some editors write.
     */
    private static String readToken(File file) throws IOException {
        String content = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        return StringUtils.trimToNull(content.startsWith("\uFEFF") ? content.substring(1) : content);
    }

    /**
     * Vault tokens are printable ASCII. Anything else would reach Vault as a different token, or be
     * rejected by the HTTP header code with an exception that quotes the value.
     */
    static void checkToken(String token) throws IOException {
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (c <= ' ' || c >= 0x7f) {
                throw new IOException("Vault token contains whitespace or characters other than printable ASCII");
            }
        }
    }
}
