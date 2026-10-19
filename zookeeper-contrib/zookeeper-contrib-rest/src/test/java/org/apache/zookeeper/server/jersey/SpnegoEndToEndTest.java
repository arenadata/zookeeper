/**
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

package org.apache.zookeeper.server.jersey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;

import org.apache.zookeeper.server.jersey.cfg.RestCfg;
import org.apache.zookeeper.server.quorum.auth.MiniKdc;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The REST gateway behind SPNEGO, against a real KDC: the server accepts a
 * Kerberos Negotiate token produced by a plain JGSS client, and still answers
 * HTTP Basic while it is configured. The requests hit a path no resource
 * serves, so a request that passes the filter shows up as Jersey's 404 and
 * no ZooKeeper server is needed.
 */
public class SpnegoEndToEndTest {

    private static final String SPNEGO_MECH_OID = "1.3.6.1.5.5.2";
    private static final String KRB5_PRINCIPAL_NAME_OID = "1.2.840.113554.1.2.2.1";
    private static final String SERVER = "HTTP/localhost";
    private static final String CLIENT = "restclient/localhost";
    private static final String UNMATCHED_PATH = "no/such/resource";

    @TempDir
    static File tempDir;

    private static MiniKdc kdc;
    private static File keytab;
    private static String realm;

    private RestMain rest;
    private String baseUrl;

    @BeforeAll
    public static void startKdc() throws Exception {
        kdc = new MiniKdc(MiniKdc.createConf(), tempDir);
        kdc.start();
        realm = kdc.getRealm();
        keytab = new File(tempDir, "rest.keytab");
        kdc.createPrincipal(keytab, SERVER, CLIENT);
    }

    @AfterAll
    public static void stopKdc() {
        kdc.stop();
    }

    @BeforeEach
    public void startRest() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        baseUrl = "http://localhost:" + port;
        RestCfg cfg = new RestCfg(new ByteArrayInputStream(String.format(
                "rest.port=%d\n"
                + "rest.endpoint.1=/;localhost:2181\n"
                + "rest.spnego.principal=%s@%s\n"
                + "rest.spnego.keytab=%s\n"
                + "rest.http.auth=probe:secret\n",
                port, SERVER, realm, keytab.getAbsolutePath()).getBytes()));
        rest = new RestMain(cfg);
        rest.start();
    }

    @AfterEach
    public void stopRest() {
        rest.stop();
    }

    @Test
    public void testUnauthenticatedRequestIsRefused() throws Exception {
        HttpURLConnection connection = get(UNMATCHED_PATH, null);
        assertEquals(401, connection.getResponseCode());
        assertTrue(challenges(connection).contains("Negotiate"),
                challenges(connection).toString());
        assertTrue(challenges(connection).contains("Basic realm=\"Restricted\""),
                challenges(connection).toString());
    }

    @Test
    public void testNegotiateTokenAuthenticates() throws Exception {
        HttpURLConnection connection = get(UNMATCHED_PATH,
                "Negotiate " + clientToken());
        assertEquals(404, connection.getResponseCode());
        assertNotNull(connection.getHeaderField("WWW-Authenticate"));
        assertTrue(connection.getHeaderField("WWW-Authenticate").startsWith("Negotiate "),
                connection.getHeaderField("WWW-Authenticate"));
    }

    @Test
    public void testGarbageNegotiateTokenIsRefused() throws Exception {
        HttpURLConnection connection = get(UNMATCHED_PATH,
                "Negotiate " + Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}));
        assertEquals(401, connection.getResponseCode());
        assertTrue(challenges(connection).contains("Negotiate"),
                challenges(connection).toString());
    }

    @Test
    public void testBasicAuthenticationStillWorks() throws Exception {
        HttpURLConnection connection = get(UNMATCHED_PATH, "Basic "
                + Base64.getEncoder().encodeToString("probe:secret".getBytes()));
        assertEquals(404, connection.getResponseCode());
    }

    private HttpURLConnection get(String path, String authorization) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(baseUrl + "/" + path)
                .openConnection();
        if (authorization != null) {
            connection.setRequestProperty("Authorization", authorization);
        }
        return connection;
    }

    private static String challenges(HttpURLConnection connection) {
        return connection.getHeaderFields().get("WWW-Authenticate").toString();
    }

    /**
     * A SPNEGO token for the gateway service principal, produced by the test
     * client principal from the same keytab.
     */
    private String clientToken() throws Exception {
        LoginContext login = new LoginContext("restclient", null, null,
                kerberosConfiguration(CLIENT + "@" + realm, keytab, true));
        login.login();
        try {
            byte[] token = Subject.doAs(login.getSubject(),
                    (PrivilegedExceptionAction<byte[]>) () -> {
                        GSSManager manager = GSSManager.getInstance();
                        GSSName serverName = manager.createName(
                                SERVER + "@" + realm, new Oid(KRB5_PRINCIPAL_NAME_OID));
                        GSSContext context = manager.createContext(serverName,
                                new Oid(SPNEGO_MECH_OID), null, GSSContext.DEFAULT_LIFETIME);
                        context.requestMutualAuth(true);
                        try {
                            return context.initSecContext(new byte[0], 0, 0);
                        } finally {
                            context.dispose();
                        }
                    });
            return Base64.getEncoder().encodeToString(token);
        } finally {
            login.logout();
        }
    }

    private static Configuration kerberosConfiguration(String principal, File keytab,
            boolean initiator) {
        java.util.Map<String, Object> options = new java.util.HashMap<>();
        options.put("useKeyTab", "true");
        options.put("keyTab", keytab.getAbsolutePath());
        options.put("principal", principal);
        options.put("storeKey", "true");
        options.put("useTicketCache", "false");
        options.put("doNotPrompt", "true");
        options.put("refreshKrb5Config", "true");
        options.put("isInitiator", Boolean.toString(initiator));
        AppConfigurationEntry entry = new AppConfigurationEntry(
                "com.sun.security.auth.module.Krb5LoginModule",
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return new AppConfigurationEntry[] {entry};
            }
        };
    }
}
