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

package org.apache.zookeeper.common;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import org.apache.zookeeper.client.ZKClientConfig;
import org.apache.zookeeper.common.vault.VaultCredentialProvider;
import org.apache.zookeeper.server.auth.DigestAuthenticationProvider;
import org.apache.zookeeper.server.auth.SaslServerCallbackHandler;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for handling secret such as key/trust store password
 */
public final class SecretUtils {
    private static final Logger LOG = LoggerFactory.getLogger(SecretUtils.class);

    /**
     * The credential provider that holds secrets otherwise set in the configuration, such as
     * {@code vault://https@bao.example.com:8200/secret/zookeeper}.
     */
    public static final String CREDENTIAL_PROVIDER_PATH = "zookeeper.credentialProvider.path";

    private static final String PROPERTY_PREFIX = "zookeeper.";

    private SecretUtils() {
    }

    /**
     * Returns the alias the credential provider stores the secret of a property under: the
     * property name without the {@code zookeeper.} prefix, as the key is written in zoo.cfg.
     */
    public static String aliasOf(String propertyName) {
        return propertyName.startsWith(PROPERTY_PREFIX) ? propertyName.substring(PROPERTY_PREFIX.length()) : propertyName;
    }

    /**
     * Returns whether a credential provider is configured.
     *
     * @param config the configuration to read the provider settings from before the system
     *               properties, or null for the system properties alone
     * @return whether {@link #CREDENTIAL_PROVIDER_PATH} is set
     */
    public static boolean hasCredentialProvider(ZKConfig config) {
        return setting(config, CREDENTIAL_PROVIDER_PATH) != null;
    }

    /**
     * Returns the secret the credential provider holds under an alias. The provider keeps what it
     * has read for the life of the process.
     *
     * @param config the configuration to read the provider settings from before the system
     *               properties, or null for the system properties alone
     * @return the secret, or null when no provider is configured or it holds no such alias
     * @throws IOException if the provider cannot be read
     */
    public static char[] getCredential(ZKConfig config, String alias) throws IOException {
        VaultCredentialProvider provider = provider(config);
        if (provider == null) {
            return null;
        }
        try {
            return provider.getCredential(alias);
        } catch (NoClassDefFoundError e) {
            throw missingJackson(e);
        }
    }

    /**
     * Reads the secrets the server looks up after startup, some of them on network threads, from the
     * credential provider, if one is configured. The start then fails while the provider is
     * unreachable, and no later lookup waits on it.
     *
     * @throws IOException if the provider cannot be read
     */
    public static void preloadCredentials() throws IOException {
        if (!hasCredentialProvider(null)) {
            return;
        }
        List<String> aliases = new ArrayList<>();
        try (X509Util clientX509Util = new ClientX509Util(); X509Util quorumX509Util = new QuorumX509Util()) {
            for (X509Util x509Util : Arrays.asList(clientX509Util, quorumX509Util)) {
                aliases.add(aliasOf(x509Util.getSslKeystorePasswdProperty()));
                aliases.add(aliasOf(x509Util.getSslTruststorePasswdProperty()));
            }
        }
        aliases.add(aliasOf(SaslServerCallbackHandler.SYSPROP_SUPER_PASSWORD));
        aliases.add(aliasOf(DigestAuthenticationProvider.SUPER_DIGEST_KEY));
        aliases.add(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_ALIAS);
        for (String alias : aliases) {
            getCredential(null, alias);
        }
    }

    /**
     * Reads the secrets of the given properties from the credential provider again, keeping those
     * read before when the provider cannot be read.
     *
     * @param config the configuration to read the provider settings from before the system
     *               properties, or null for the system properties alone
     */
    public static void refreshCredentials(ZKConfig config, String... propertyNames) {
        try {
            VaultCredentialProvider provider = provider(config);
            if (provider != null) {
                for (String propertyName : propertyNames) {
                    provider.refresh(aliasOf(propertyName));
                }
            }
        } catch (IOException e) {
            LOG.warn("Keeping the credentials read earlier", e);
        } catch (NoClassDefFoundError e) {
            LOG.warn("Keeping the credentials read earlier", missingJackson(e));
        }
    }

    private static VaultCredentialProvider provider(ZKConfig config) throws IOException {
        String path = setting(config, CREDENTIAL_PROVIDER_PATH);
        if (path == null) {
            return null;
        }
        URI uri;
        try {
            uri = new URI(path);
        } catch (URISyntaxException e) {
            throw new IOException("Invalid " + CREDENTIAL_PROVIDER_PATH + " " + path, e);
        }
        if (!VaultCredentialProvider.SCHEME.equalsIgnoreCase(uri.getScheme())) {
            throw new IOException("Unsupported credential provider " + path + ": only "
                + VaultCredentialProvider.SCHEME + ":// is supported");
        }
        Function<String, String> settings = key -> setting(config, key);
        if (config instanceof ZKClientConfig) {
            // a client logs in with its own JAAS section unless one is configured for Vault
            settings = key -> {
                String value = setting(config, key);
                return value == null && key.equals(VaultCredentialProvider.KERBEROS_LOGIN_CONTEXT)
                    ? config.getProperty(ZKClientConfig.LOGIN_CONTEXT_NAME_KEY, ZKClientConfig.LOGIN_CONTEXT_NAME_KEY_DEFAULT)
                    : value;
            };
        }
        try {
            return VaultCredentialProvider.get(uri, settings);
        } catch (NoClassDefFoundError e) {
            throw missingJackson(e);
        }
    }

    /**
     * jackson-databind is a provided dependency: the server distribution ships it, a client
     * application has to add it.
     */
    private static IOException missingJackson(NoClassDefFoundError e) {
        return new IOException("The " + VaultCredentialProvider.SCHEME
            + ":// credential provider needs jackson-databind on the classpath", e);
    }

    /**
     * Returns the password a property configures: the credential provider's secret stored under
     * the alias of the property, else the content of the file named by the path property, else
     * the property value, else the empty string.
     *
     * @param propertyName the password property
     * @param pathPropertyName the property naming a file that holds the password
     * @throws IllegalStateException if the credential provider or the file cannot be read
     */
    public static String getPassword(ZKConfig config, String propertyName, String pathPropertyName) {
        String alias = aliasOf(propertyName);
        char[] credential;
        try {
            credential = getCredential(config, alias);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read " + alias + " from the credential provider", e);
        }
        if (credential != null) {
            return String.valueOf(credential);
        }
        String path = config.getProperty(pathPropertyName, "");
        if (!path.isEmpty()) {
            return String.valueOf(readSecret(path));
        }
        return config.getProperty(propertyName, "");
    }

    private static String setting(ZKConfig config, String key) {
        String value = config == null ? null : config.getProperty(key);
        return StringUtils.trimToNull(value == null ? System.getProperty(key) : value);
    }

    public static char[] readSecret(final String pathToFile) {
        LOG.info("Reading secret from {}", pathToFile);

        try {
            final String secretValue = new String(
                    Files.readAllBytes(Paths.get(pathToFile)), StandardCharsets.UTF_8);

            if (secretValue.endsWith(System.lineSeparator())) {
                return secretValue.substring(0, secretValue.length() - System.lineSeparator().length()).toCharArray();
            }

            return secretValue.toCharArray();
        } catch (final Throwable e) {
            LOG.error("Exception occurred when reading secret from file {}", pathToFile, e);
            throw new IllegalStateException("Exception occurred when reading secret from file " + pathToFile, e);
        }
    }
}
