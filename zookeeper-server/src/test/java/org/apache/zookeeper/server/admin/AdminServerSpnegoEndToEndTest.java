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

package org.apache.zookeeper.server.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import org.apache.zookeeper.server.ZooKeeperServer;
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
 * The admin server behind SPNEGO, against a real KDC: a Negotiate token
 * produced by a plain JGSS client authenticates, the default allowlist
 * admits mntr, and blocked commands answer 403 to an authenticated client.
 * mntr runs without a live ZooKeeperServer, so none is started.
 */
public class AdminServerSpnegoEndToEndTest {

    private static final String SPNEGO_MECH_OID = "1.3.6.1.5.5.2";
    private static final String KRB5_PRINCIPAL_NAME_OID = "1.2.840.113554.1.2.2.1";
    private static final String SERVER = "HTTP/localhost";
    private static final String CLIENT = "adminclient/localhost";

    @TempDir
    static File tempDir;

    private static MiniKdc kdc;
    private static File keytab;
    private static String realm;

    private JettyAdminServer adminServer;
    private String baseUrl;

    @BeforeAll
    public static void startKdc() throws Exception {
        kdc = new MiniKdc(MiniKdc.createConf(), tempDir);
        kdc.start();
        realm = kdc.getRealm();
        keytab = new File(tempDir, "admin.keytab");
        kdc.createPrincipal(keytab, SERVER, CLIENT);
    }

    @AfterAll
    public static void stopKdc() {
        kdc.stop();
    }

    @BeforeEach
    public void startAdminServer() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        System.setProperty("zookeeper.admin.spnego.principal", SERVER + "@" + realm);
        System.setProperty("zookeeper.admin.spnego.keytab", keytab.getAbsolutePath());
        adminServer = new JettyAdminServer("127.0.0.1", port, 30000, "/commands",
            11, false, false, false);
        // mntr dereferences the server; an unstarted instance is enough for it
        adminServer.setZooKeeperServer(new ZooKeeperServer(tempDir, tempDir, 3000));
        adminServer.start();
        baseUrl = "http://127.0.0.1:" + port + "/commands";
    }

    @AfterEach
    public void stopAdminServer() throws Exception {
        System.clearProperty("zookeeper.admin.spnego.principal");
        System.clearProperty("zookeeper.admin.spnego.keytab");
        adminServer.shutdown();
    }

    @Test
    public void testUnauthenticatedRequestIsRefused() throws Exception {
        HttpURLConnection connection = get("/mntr", null);
        assertEquals(401, connection.getResponseCode());
        assertTrue(connection.getHeaderFields().get("WWW-Authenticate").toString().contains("Negotiate"),
            connection.getHeaderFields().get("WWW-Authenticate").toString());
    }

    @Test
    public void testNegotiateTokenRunsMonitor() throws Exception {
        HttpURLConnection connection = get("/mntr", "Negotiate " + clientToken());
        int status = connection.getResponseCode();
        String content = status == 200 ? body(connection) : errorBody(connection);
        assertEquals(200, status, content);
        assertTrue(content.contains("monitor"), content);
    }

    @Test
    public void testCommandOutsideAllowlistIsBlocked() throws Exception {
        HttpURLConnection connection = get("/cons", "Negotiate " + clientToken());
        assertEquals(403, connection.getResponseCode());
    }

    @Test
    public void testNeverCommandIsBlocked() throws Exception {
        HttpURLConnection connection = get("/srst", "Negotiate " + clientToken());
        assertEquals(403, connection.getResponseCode());
    }

    private HttpURLConnection get(String path, String authorization) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        if (authorization != null) {
            connection.setRequestProperty("Authorization", authorization);
        }
        return connection;
    }

    private static String body(HttpURLConnection connection) throws IOException {
        StringBuilder body = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                connection.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                body.append(line);
            }
        }
        return body.toString();
    }

    private static String errorBody(HttpURLConnection connection) throws IOException {
        if (connection.getErrorStream() == null) {
            return "<no error body>";
        }
        StringBuilder body = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                connection.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                body.append(line);
            }
        }
        return body.toString();
    }

    /**
     * A SPNEGO token for the admin service principal, produced by the test
     * client principal from the same keytab.
     */
    private String clientToken() throws Exception {
        LoginContext login = new LoginContext("adminclient", null, null,
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
        Map<String, Object> options = new HashMap<>();
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
