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

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.apache.zookeeper.common.X509Util;
import org.apache.zookeeper.server.ZooKeeperSaslServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads credentials from a KV v2 secrets engine of HashiCorp Vault or OpenBao. The URI and the
 * secret layout are those of the Hadoop {@code vault://} credential provider, so
 * {@code hadoop credential create} writes secrets this provider reads.
 *
 * <p>A provider is shared by every lookup with the same settings: the process logs in once, and
 * again only when Vault refuses its token. Credentials themselves are read afresh at each lookup.
 */
public final class VaultCredentialProvider {

    private static final Logger LOG = LoggerFactory.getLogger(VaultCredentialProvider.class);

    public static final String SCHEME = "vault";
    public static final String PREFIX = "zookeeper.credentialProvider.vault.";
    public static final String AUTH_METHOD = PREFIX + "authMethod";
    public static final String AUTH_METHOD_TOKEN = "token";
    public static final String AUTH_METHOD_KERBEROS = "kerberos";
    public static final String TOKEN_PATH = PREFIX + "tokenPath";
    public static final String KERBEROS_LOGIN_CONTEXT = PREFIX + "kerberos.loginContext";
    public static final String KERBEROS_SERVICE_PRINCIPAL = PREFIX + "kerberos.servicePrincipal";
    public static final String KERBEROS_MOUNT_PATH = PREFIX + "kerberos.mountPath";
    public static final String KERBEROS_MOUNT_PATH_DEFAULT = "auth/kerberos";
    public static final String KERBEROS_ROLE = PREFIX + "kerberos.role";
    public static final String TRUSTSTORE_LOCATION = PREFIX + "ssl.trustStore.location";
    public static final String TRUSTSTORE_PASSWORD = PREFIX + "ssl.trustStore.password";
    public static final String TRUSTSTORE_TYPE = PREFIX + "ssl.trustStore.type";
    public static final String CONNECT_TIMEOUT_MS = PREFIX + "connectTimeoutMs";
    public static final String READ_TIMEOUT_MS = PREFIX + "readTimeoutMs";
    public static final String RETRY_COUNT = PREFIX + "retryCount";
    public static final String RETRY_INTERVAL_MS = PREFIX + "retryIntervalMs";

    private static final int CONNECT_TIMEOUT_MS_DEFAULT = 30000;
    private static final int READ_TIMEOUT_MS_DEFAULT = 30000;
    private static final int RETRY_COUNT_DEFAULT = 3;
    private static final int RETRY_INTERVAL_MS_DEFAULT = 1000;

    /** Properties that shape a provider; providers are shared only when all of them match. */
    private static final String[] SETTINGS = {
        AUTH_METHOD, TOKEN_PATH, KERBEROS_LOGIN_CONTEXT, ZooKeeperSaslServer.LOGIN_CONTEXT_NAME_KEY,
        KERBEROS_SERVICE_PRINCIPAL, KERBEROS_MOUNT_PATH, KERBEROS_ROLE, TRUSTSTORE_LOCATION,
        TRUSTSTORE_PASSWORD, TRUSTSTORE_TYPE, CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS, RETRY_COUNT,
        RETRY_INTERVAL_MS,
    };

    private static final ConcurrentMap<List<String>, VaultCredentialProvider> PROVIDERS = new ConcurrentHashMap<>();

    private final VaultConnectionInfo connInfo;
    private final VaultHttpClient client;

    private VaultCredentialProvider(VaultConnectionInfo connInfo, VaultHttpClient client) {
        this.connInfo = connInfo;
        this.client = client;
    }

    /**
     * Returns the provider of a URI, created on first use.
     *
     * @param uri the provider URI
     * @param settings the value of a configuration property, null when it is not set
     * @return the provider
     * @throws IOException if the URI or the settings are invalid
     */
    public static VaultCredentialProvider get(URI uri, Function<String, String> settings) throws IOException {
        List<String> key = new ArrayList<>();
        key.add(uri.toString());
        for (String setting : SETTINGS) {
            key.add(setting(settings, setting));
        }
        VaultCredentialProvider provider = PROVIDERS.get(key);
        if (provider == null) {
            VaultCredentialProvider created = create(uri, settings);
            provider = PROVIDERS.putIfAbsent(key, created);
            if (provider == null) {
                provider = created;
            }
        }
        return provider;
    }

    // VisibleForTesting
    static void clearProviders() {
        PROVIDERS.clear();
    }

    private static VaultCredentialProvider create(URI uri, Function<String, String> settings) throws IOException {
        VaultConnectionInfo connInfo = new VaultConnectionInfo(uri);
        String method = setting(settings, AUTH_METHOD);
        VaultAuthMethod authMethod;
        if (method == null || method.equalsIgnoreCase(AUTH_METHOD_TOKEN)) {
            authMethod = new TokenVaultAuth(setting(settings, TOKEN_PATH), System::getenv);
        } else if (method.equalsIgnoreCase(AUTH_METHOD_KERBEROS)) {
            String mountPath = setting(settings, KERBEROS_MOUNT_PATH);
            authMethod = new KerberosVaultAuth(connInfo, loginContext(settings),
                setting(settings, KERBEROS_SERVICE_PRINCIPAL),
                mountPath == null ? KERBEROS_MOUNT_PATH_DEFAULT : mountPath,
                setting(settings, KERBEROS_ROLE));
        } else {
            throw new IOException("Unsupported " + AUTH_METHOD + " '" + method + "'; expected "
                + AUTH_METHOD_TOKEN + " or " + AUTH_METHOD_KERBEROS);
        }
        VaultHttpClient client = new VaultHttpClient(connInfo, authMethod,
            number(settings, CONNECT_TIMEOUT_MS, CONNECT_TIMEOUT_MS_DEFAULT),
            number(settings, READ_TIMEOUT_MS, READ_TIMEOUT_MS_DEFAULT),
            number(settings, RETRY_COUNT, RETRY_COUNT_DEFAULT),
            number(settings, RETRY_INTERVAL_MS, RETRY_INTERVAL_MS_DEFAULT),
            connInfo.isHttps() ? sslSocketFactory(settings) : null);
        LOG.info("Reading credentials from {} with {} auth", connInfo,
            method == null ? AUTH_METHOD_TOKEN : method.toLowerCase(Locale.ROOT));
        return new VaultCredentialProvider(connInfo, client);
    }

    /**
     * The JAAS section of the ZooKeeper server login unless one is configured for Vault.
     */
    private static String loginContext(Function<String, String> settings) {
        String loginContext = setting(settings, KERBEROS_LOGIN_CONTEXT);
        if (loginContext == null) {
            loginContext = setting(settings, ZooKeeperSaslServer.LOGIN_CONTEXT_NAME_KEY);
        }
        return loginContext == null ? ZooKeeperSaslServer.DEFAULT_LOGIN_CONTEXT_NAME : loginContext;
    }

    /**
     * The JVM default unless a trust store is configured for Vault.
     */
    private static SSLSocketFactory sslSocketFactory(Function<String, String> settings) throws IOException {
        String location = setting(settings, TRUSTSTORE_LOCATION);
        if (location == null) {
            return null;
        }
        try {
            KeyStore trustStore = X509Util.loadTrustStore(location, setting(settings, TRUSTSTORE_PASSWORD),
                setting(settings, TRUSTSTORE_TYPE));
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            return sslContext.getSocketFactory();
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IOException("Failed to load the Vault trust store " + location, e);
        }
    }

    private static String setting(Function<String, String> settings, String key) {
        String value = settings.apply(key);
        if (value == null) {
            return null;
        }
        value = value.trim();
        return value.isEmpty() ? null : value;
    }

    private static int number(Function<String, String> settings, String key, int defaultValue) throws IOException {
        String value = setting(settings, key);
        if (value == null) {
            return defaultValue;
        }
        try {
            int number = Integer.parseInt(value);
            if (number < 0) {
                throw new IOException(key + " must not be negative: " + value);
            }
            return number;
        } catch (NumberFormatException e) {
            throw new IOException(key + " is not a number: " + value, e);
        }
    }

    /**
     * Returns the credential stored under an alias.
     *
     * @param alias the alias
     * @return the credential, or null when Vault holds no such alias
     * @throws IOException if Vault cannot be read
     */
    public char[] getCredential(String alias) throws IOException {
        VaultConnectionInfo.checkPath(alias);
        String value = client.readField(connInfo.dataPath(alias), connInfo.getField());
        if (value == null) {
            LOG.debug("{} holds no {}", connInfo, alias);
            return null;
        }
        LOG.info("Read {} from {}", alias, connInfo);
        return value.toCharArray();
    }
}
