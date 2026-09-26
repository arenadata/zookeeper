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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import org.apache.commons.io.IOUtils;

/**
 * A KV v2 engine, token lookup and a Kerberos auth method served over HTTP or HTTPS by
 * {@code com.sun.net.httpserver}.
 */
public final class MockVault implements AutoCloseable {

    public static final String TOKEN = "s.mock-token";
    public static final String KERBEROS_LOGIN_PATH = "/v1/auth/kerberos/login";
    public static final String LOOKUP_SELF_PATH = "/v1/auth/token/lookup-self";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Checks the SPNEGO token of a Kerberos login.
     */
    public interface LoginHandler {

        /**
         * Returns the client token to issue, or null to refuse the login.
         *
         * @param authorization the Authorization header of the login request
         */
        String login(String authorization) throws Exception;
    }

    private final HttpServer server;
    private final String protocol;
    private final Map<String, ObjectNode> secrets = new ConcurrentHashMap<>();
    private final Map<String, String> rawResponses = new ConcurrentHashMap<>();
    private final Map<String, String> deletedVersions = new ConcurrentHashMap<>();
    private final List<String> requests = new CopyOnWriteArrayList<>();
    private final Set<String> acceptedTokens = ConcurrentHashMap.newKeySet();
    private final Set<String> deniedPaths = ConcurrentHashMap.newKeySet();
    private final List<String> loginRoles = new CopyOnWriteArrayList<>();
    private final AtomicInteger reads = new AtomicInteger();
    private final AtomicInteger failures = new AtomicInteger();
    private final AtomicInteger lookupFailures = new AtomicInteger();
    private final AtomicInteger requestsWithoutHeader = new AtomicInteger();
    private volatile int lookupFailureStatus;
    private volatile int failureStatus;
    private volatile String failureBody;
    private volatile LoginHandler loginHandler;
    private volatile String loginRedirect;

    public MockVault() throws IOException {
        this(null);
    }

    /**
     * Serves HTTPS with the given server context, or HTTP when it is null.
     */
    public MockVault(SSLContext sslContext) throws IOException {
        InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        if (sslContext == null) {
            server = HttpServer.create(address, 0);
            protocol = "http";
        } else {
            HttpsServer httpsServer = HttpsServer.create(address, 0);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));
            server = httpsServer;
            protocol = "https";
        }
        server.createContext("/v1/", this::handle);
        server.start();
        acceptedTokens.add(TOKEN);
    }

    /**
     * The provider URI of a KV path on this server, such as {@code secret/zookeeper}.
     */
    public String uri(String path) {
        return "vault://" + protocol + "@localhost:" + port() + "/" + path;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    /**
     * Stores a field of the secret at a KV v2 data path such as {@code secret/data/zookeeper/alias}.
     */
    public void putSecret(String dataPath, String field, String value) {
        secrets.computeIfAbsent(dataPath, path -> MAPPER.createObjectNode()).put(field, value);
    }

    /**
     * Answers reads of a KV v2 data path with 200 and the given body.
     */
    public void putRaw(String dataPath, String body) {
        rawResponses.put(dataPath, body);
    }

    /**
     * Stores a field of a secret whose JSON value is not a string.
     */
    public void putSecretJson(String dataPath, String field, String json) throws IOException {
        secrets.computeIfAbsent(dataPath, path -> MAPPER.createObjectNode()).set(field, MAPPER.readTree(json));
    }

    /**
     * Answers reads of a KV v2 data path with the 404 of a deleted latest version, which carries the
     * metadata of the secret.
     */
    public void putDeleted(String dataPath, String customMetadataJson) {
        deletedVersions.put(dataPath, customMetadataJson);
    }

    /**
     * Answers the next {@code count} token lookups with {@code status}.
     */
    public void failLookups(int status, int count) {
        lookupFailureStatus = status;
        lookupFailures.set(count);
    }

    /**
     * The number of requests that came without an {@code X-Vault-Request} header.
     */
    public int requestsWithoutHeader() {
        return requestsWithoutHeader.get();
    }

    public void acceptToken(String token) {
        acceptedTokens.add(token);
    }

    public void revokeToken(String token) {
        acceptedTokens.remove(token);
    }

    public void setLoginHandler(LoginHandler loginHandler) {
        this.loginHandler = loginHandler;
    }

    /**
     * Answers reads of a KV v2 data path with the 403 of a policy that does not cover it.
     */
    public void deny(String dataPath) {
        deniedPaths.add(dataPath);
    }

    /**
     * Answers Kerberos logins with a 307 to the same path on another server, as a standby does.
     */
    public void redirectLoginTo(MockVault active) {
        loginRedirect = active.protocol + "://localhost:" + active.port() + KERBEROS_LOGIN_PATH;
    }

    /**
     * Answers the next {@code count} requests with {@code status}.
     */
    public void fail(int status, int count) {
        fail(status, count, "{\"errors\":[\"injected failure\"]}");
    }

    public void fail(int status, int count, String body) {
        failureStatus = status;
        failureBody = body;
        failures.set(count);
    }

    /**
     * Every request received, as method and path.
     */
    public List<String> requests() {
        return requests;
    }

    /**
     * The number of secret reads answered with a secret or a 404.
     */
    public int reads() {
        return reads.get();
    }

    /**
     * The {@code role} field of every login request, null where it was not sent.
     */
    public List<String> loginRoles() {
        return loginRoles;
    }

    private void handle(HttpExchange exchange) throws IOException {
        String body = IOUtils.toString(exchange.getRequestBody(), StandardCharsets.UTF_8);
        String path = exchange.getRequestURI().getPath();
        requests.add(exchange.getRequestMethod() + " " + path);
        if (!"true".equals(exchange.getRequestHeaders().getFirst("X-Vault-Request"))) {
            requestsWithoutHeader.incrementAndGet();
        }
        if (failures.getAndUpdate(n -> n > 0 ? n - 1 : 0) > 0) {
            respond(exchange, failureStatus, failureBody);
            return;
        }
        if (path.equals(KERBEROS_LOGIN_PATH) && exchange.getRequestMethod().equals("POST")) {
            String redirect = loginRedirect;
            if (redirect != null) {
                exchange.getResponseHeaders().set("Location", redirect);
                respond(exchange, 307, "");
                return;
            }
            login(exchange, body);
            return;
        }
        String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");
        boolean accepted = token != null && acceptedTokens.contains(token);
        if (path.equals(LOOKUP_SELF_PATH)) {
            if (lookupFailures.getAndUpdate(n -> n > 0 ? n - 1 : 0) > 0) {
                respond(exchange, lookupFailureStatus, "{\"errors\":[\"injected failure\"]}");
                return;
            }
            respond(exchange, accepted ? 200 : 403, accepted ? "{\"data\":{}}" : "{\"errors\":[\"permission denied\"]}");
            return;
        }
        String dataPath = path.substring("/v1/".length());
        if (!exchange.getRequestMethod().equals("GET") || !dataPath.startsWith("secret/data/")) {
            respond(exchange, 404, "{\"errors\":[\"no handler for route \\\"" + dataPath + "\\\"\"]}");
            return;
        }
        if (!accepted || deniedPaths.contains(dataPath)) {
            respond(exchange, 403, "{\"errors\":[\"permission denied\"]}");
            return;
        }
        reads.incrementAndGet();
        String raw = rawResponses.get(dataPath);
        if (raw != null) {
            respond(exchange, 200, raw);
            return;
        }
        String deleted = deletedVersions.get(dataPath);
        if (deleted != null) {
            respond(exchange, 404, "{\"request_id\":\"1\",\"data\":{\"data\":null,\"metadata\":{\"custom_metadata\":"
                + deleted + ",\"deletion_time\":\"2026-01-01T00:00:00Z\",\"destroyed\":false,\"version\":2}},"
                + "\"warnings\":null}");
            return;
        }
        ObjectNode fields = secrets.get(dataPath);
        if (fields == null) {
            respond(exchange, 404, "{\"errors\":[]}");
            return;
        }
        ObjectNode response = MAPPER.createObjectNode();
        response.putObject("data").set("data", fields);
        respond(exchange, 200, response.toString());
    }

    private void login(HttpExchange exchange, String body) throws IOException {
        JsonNode request = body.isEmpty() ? MAPPER.createObjectNode() : MAPPER.readTree(body);
        loginRoles.add(request.path("role").asText(null));
        LoginHandler handler = loginHandler;
        String token;
        try {
            token = handler == null ? null : handler.login(exchange.getRequestHeaders().getFirst("Authorization"));
        } catch (Exception e) {
            token = null;
        }
        if (token == null) {
            respond(exchange, 403, "{\"errors\":[\"login refused\"]}");
            return;
        }
        acceptedTokens.add(token);
        ObjectNode response = MAPPER.createObjectNode();
        response.putObject("auth").put("client_token", token);
        respond(exchange, 200, response.toString());
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
