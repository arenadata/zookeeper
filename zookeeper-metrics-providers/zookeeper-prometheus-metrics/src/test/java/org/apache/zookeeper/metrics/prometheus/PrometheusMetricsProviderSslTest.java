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

package org.apache.zookeeper.metrics.prometheus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import io.prometheus.client.CollectorRegistry;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.apache.zookeeper.metrics.MetricsProviderLifeCycleException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for the HTTPS support of the /metrics endpoint.
 */
public class PrometheusMetricsProviderSslTest {

    private static final String PASSWORD = "testpass";
    private static final String KEY_PASSWORD = "keytestpass";

    @TempDir
    static Path certDir;

    private static String serverKeyStore;
    private static String serverTrustStore;
    private static String clientKeyStore;
    private static String clientTrustStore;
    private static String jksKeyStoreWithKeyPassword;
    private static String passwordFile;

    @BeforeAll
    public static void generateCertificates() throws Exception {
        serverKeyStore = certDir.resolve("server.p12").toString();
        serverTrustStore = certDir.resolve("servertrust.p12").toString();
        clientKeyStore = certDir.resolve("client.p12").toString();
        clientTrustStore = certDir.resolve("clienttrust.p12").toString();
        String serverCert = certDir.resolve("server.crt").toString();
        String clientCert = certDir.resolve("client.crt").toString();

        // the server certificate deliberately has no SAN matching "localhost", so that
        // hostname-based requests carrying SNI would be rejected by Jetty's SNI host check
        // if it were left enabled
        keytool("-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-dname", "CN=zk-metrics-test", "-ext", "san=ip:127.0.0.1",
                "-keystore", serverKeyStore, "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-keypass", PASSWORD);
        keytool("-exportcert", "-alias", "server", "-keystore", serverKeyStore,
                "-storepass", PASSWORD, "-file", serverCert);
        keytool("-importcert", "-noprompt", "-alias", "server", "-file", serverCert,
                "-keystore", clientTrustStore, "-storetype", "PKCS12", "-storepass", PASSWORD);

        keytool("-genkeypair", "-alias", "client", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-dname", "CN=zk-metrics-test-client",
                "-keystore", clientKeyStore, "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-keypass", PASSWORD);
        keytool("-exportcert", "-alias", "client", "-keystore", clientKeyStore,
                "-storepass", PASSWORD, "-file", clientCert);
        keytool("-importcert", "-noprompt", "-alias", "client", "-file", clientCert,
                "-keystore", serverTrustStore, "-storetype", "PKCS12", "-storepass", PASSWORD);

        // JKS keystore whose private key password differs from the store password
        // (PKCS12 does not support this, so JKS is used here)
        jksKeyStoreWithKeyPassword = certDir.resolve("server-keypass.jks").toString();
        String jksCert = certDir.resolve("server-keypass.crt").toString();
        keytool("-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-dname", "CN=zk-metrics-test", "-ext", "san=ip:127.0.0.1",
                "-keystore", jksKeyStoreWithKeyPassword, "-storetype", "JKS",
                "-storepass", PASSWORD, "-keypass", KEY_PASSWORD);
        keytool("-exportcert", "-alias", "server", "-keystore", jksKeyStoreWithKeyPassword,
                "-storepass", PASSWORD, "-file", jksCert);
        keytool("-importcert", "-noprompt", "-alias", "server-keypass", "-file", jksCert,
                "-keystore", clientTrustStore, "-storetype", "PKCS12", "-storepass", PASSWORD);

        passwordFile = certDir.resolve("keystore-password.txt").toString();
        Files.write(Paths.get(passwordFile), (PASSWORD + System.lineSeparator()).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testHttpsMetricsEndpoint() throws Exception {
        PrometheusMetricsProvider provider = startSslProvider(false, false);
        try {
            SSLContext clientContext = createClientSslContext(false);
            int port = provider.getServerPort();
            // scraping by IP address sends no SNI
            assertEquals(200, fetchStatus("https://127.0.0.1:" + port + "/metrics", clientContext));
            // scraping by hostname sends SNI; the certificate has no matching SAN, so this
            // only works because hostname verification is disabled by default
            assertEquals(200, fetchStatus("https://localhost:" + port + "/metrics", clientContext));
        } finally {
            provider.stop();
        }
    }

    @Test
    public void testHttpsMetricsEndpointWithHostnameVerification() throws Exception {
        PrometheusMetricsProvider provider = startSslProvider(false, true);
        try {
            SSLContext clientContext = createClientSslContext(false);
            int port = provider.getServerPort();
            // requests without SNI are still accepted with the check enabled
            assertEquals(200, fetchStatus("https://127.0.0.1:" + port + "/metrics", clientContext));
        } finally {
            provider.stop();
        }
    }

    @Test
    public void testKeystorePasswordFromFile() throws Exception {
        Properties overrides = new Properties();
        overrides.setProperty("ssl.keyStore.password", "");
        overrides.setProperty("ssl.keyStore.passwordPath", passwordFile);
        PrometheusMetricsProvider provider = startSslProvider(false, false, overrides);
        try {
            SSLContext clientContext = createClientSslContext(false);
            int port = provider.getServerPort();
            assertEquals(200, fetchStatus("https://127.0.0.1:" + port + "/metrics", clientContext));
        } finally {
            provider.stop();
        }
    }

    @Test
    public void testSeparateKeyPassword() throws Exception {
        Properties overrides = new Properties();
        overrides.setProperty("ssl.keyStore.location", jksKeyStoreWithKeyPassword);
        overrides.setProperty("ssl.keyStore.type", "JKS");
        overrides.setProperty("ssl.keyStore.keyPassword", KEY_PASSWORD);
        PrometheusMetricsProvider provider = startSslProvider(false, false, overrides);
        try {
            SSLContext clientContext = createClientSslContext(false);
            int port = provider.getServerPort();
            assertEquals(200, fetchStatus("https://127.0.0.1:" + port + "/metrics", clientContext));
        } finally {
            provider.stop();
        }
    }

    @Test
    public void testEnabledProtocolsAndCipherSuites() throws Exception {
        Properties overrides = new Properties();
        overrides.setProperty("ssl.enabledProtocols", "TLSv1.2");
        overrides.setProperty("ssl.ciphersuites", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        PrometheusMetricsProvider provider = startSslProvider(false, false, overrides);
        try {
            SSLContext clientContext = createClientSslContext(false);
            int port = provider.getServerPort();
            try (SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket("127.0.0.1", port)) {
                socket.setEnabledProtocols(new String[]{"TLSv1.3"});
                assertThrows(IOException.class, socket::startHandshake);
            }
            try (SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket("127.0.0.1", port)) {
                socket.setEnabledProtocols(new String[]{"TLSv1.2"});
                socket.startHandshake();
                assertEquals("TLSv1.2", socket.getSession().getProtocol());
                assertEquals("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", socket.getSession().getCipherSuite());
            }
            assertEquals(200, fetchStatus("https://127.0.0.1:" + port + "/metrics", clientContext));
        } finally {
            provider.stop();
        }
    }

    @Test
    public void testNeedClientAuthRequiresTruststore() {
        assertThrows(MetricsProviderLifeCycleException.class, () -> {
            CollectorRegistry.defaultRegistry.clear();
            PrometheusMetricsProvider provider = new PrometheusMetricsProvider();
            Properties configuration = new Properties();
            configuration.setProperty("ssl.enabled", "true");
            configuration.setProperty("ssl.keyStore.location", serverKeyStore);
            configuration.setProperty("ssl.keyStore.password", PASSWORD);
            configuration.setProperty("ssl.needClientAuth", "true");
            provider.configure(configuration);
        });
    }

    @Test
    public void testClientAuthRejectsClientWithoutCertificate() throws Exception {
        PrometheusMetricsProvider provider = startSslProvider(true, false);
        try {
            SSLContext clientContext = createClientSslContext(false);
            int port = provider.getServerPort();
            assertThrows(IOException.class,
                    () -> fetchStatus("https://127.0.0.1:" + port + "/metrics", clientContext));
        } finally {
            provider.stop();
        }
    }

    @Test
    public void testClientAuthAcceptsClientWithCertificate() throws Exception {
        PrometheusMetricsProvider provider = startSslProvider(true, false);
        try {
            SSLContext clientContext = createClientSslContext(true);
            int port = provider.getServerPort();
            assertEquals(200, fetchStatus("https://127.0.0.1:" + port + "/metrics", clientContext));
        } finally {
            provider.stop();
        }
    }

    private static PrometheusMetricsProvider startSslProvider(boolean needClientAuth, boolean hostnameVerification)
            throws MetricsProviderLifeCycleException {
        return startSslProvider(needClientAuth, hostnameVerification, new Properties());
    }

    private static PrometheusMetricsProvider startSslProvider(boolean needClientAuth, boolean hostnameVerification,
            Properties overrides) throws MetricsProviderLifeCycleException {
        CollectorRegistry.defaultRegistry.clear();
        PrometheusMetricsProvider provider = new PrometheusMetricsProvider();
        Properties configuration = new Properties();
        configuration.setProperty("httpHost", "127.0.0.1");
        configuration.setProperty("httpPort", "0");
        configuration.setProperty("exportJvmInfo", "false");
        configuration.setProperty("ssl.enabled", "true");
        configuration.setProperty("ssl.keyStore.location", serverKeyStore);
        configuration.setProperty("ssl.keyStore.password", PASSWORD);
        configuration.setProperty("ssl.keyStore.type", "PKCS12");
        configuration.setProperty("ssl.hostnameVerification", Boolean.toString(hostnameVerification));
        if (needClientAuth) {
            configuration.setProperty("ssl.trustStore.location", serverTrustStore);
            configuration.setProperty("ssl.trustStore.password", PASSWORD);
            configuration.setProperty("ssl.trustStore.type", "PKCS12");
            configuration.setProperty("ssl.needClientAuth", "true");
        }
        configuration.putAll(overrides);
        provider.configure(configuration);
        provider.start();
        return provider;
    }

    private static SSLContext createClientSslContext(boolean withClientCertificate) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(loadKeyStore(clientTrustStore));

        KeyManagerFactory kmf = null;
        if (withClientCertificate) {
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(loadKeyStore(clientKeyStore), PASSWORD.toCharArray());
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslContext;
    }

    private static KeyStore loadKeyStore(String location) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream inputStream = new FileInputStream(location)) {
            keyStore.load(inputStream, PASSWORD.toCharArray());
        }
        return keyStore;
    }

    private static int fetchStatus(String url, SSLContext sslContext) throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        connection.setHostnameVerifier((hostname, session) -> true);
        try {
            return connection.getResponseCode();
        } finally {
            connection.disconnect();
        }
    }

    private static void keytool(String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Paths.get(System.getProperty("java.home"), "bin", "keytool").toString());
        command.addAll(Arrays.asList(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        byte[] output = new byte[4096];
        int length = process.getInputStream().read(output);
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IllegalStateException("keytool failed with exit code " + exitCode + ": "
                    + new String(output, 0, Math.max(length, 0)));
        }
    }

}
