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
import org.apache.commons.io.IOUtils;

/**
 * A KV v2 engine and a Kerberos auth method served over HTTP by {@code com.sun.net.httpserver}.
 */
public final class MockVault implements AutoCloseable {

    public static final String TOKEN = "s.mock-token";
    public static final String KERBEROS_LOGIN_PATH = "/v1/auth/kerberos/login";

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
    private final Map<String, ObjectNode> secrets = new ConcurrentHashMap<>();
    private final Set<String> acceptedTokens = ConcurrentHashMap.newKeySet();
    private final List<String> loginRoles = new CopyOnWriteArrayList<>();
    private final AtomicInteger reads = new AtomicInteger();
    private final AtomicInteger failures = new AtomicInteger();
    private volatile int failureStatus;
    private volatile LoginHandler loginHandler;

    public MockVault() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/v1/", this::handle);
        server.start();
        acceptedTokens.add(TOKEN);
    }

    /**
     * The provider URI of a KV path on this server, such as {@code secret/zookeeper}.
     */
    public String uri(String path) {
        return "vault://http@localhost:" + server.getAddress().getPort() + "/" + path;
    }

    /**
     * Stores a field of the secret at a KV v2 data path such as {@code secret/data/zookeeper/alias}.
     */
    public void putSecret(String dataPath, String field, String value) {
        secrets.computeIfAbsent(dataPath, path -> MAPPER.createObjectNode()).put(field, value);
    }

    /**
     * Stores a field of a secret whose JSON value is not a string.
     */
    public void putSecretJson(String dataPath, String field, String json) throws IOException {
        secrets.computeIfAbsent(dataPath, path -> MAPPER.createObjectNode()).set(field, MAPPER.readTree(json));
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
     * Answers the next {@code count} requests with {@code status}.
     */
    public void fail(int status, int count) {
        failureStatus = status;
        failures.set(count);
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
        if (failures.getAndUpdate(n -> n > 0 ? n - 1 : 0) > 0) {
            respond(exchange, failureStatus, "{\"errors\":[\"injected failure\"]}");
            return;
        }
        String path = exchange.getRequestURI().getPath();
        if (path.equals(KERBEROS_LOGIN_PATH) && exchange.getRequestMethod().equals("POST")) {
            login(exchange, body);
            return;
        }
        String dataPath = path.substring("/v1/".length());
        if (!exchange.getRequestMethod().equals("GET") || !dataPath.startsWith("secret/data/")) {
            respond(exchange, 404, "{\"errors\":[\"no handler for route \\\"" + dataPath + "\\\"\"]}");
            return;
        }
        String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");
        if (token == null || !acceptedTokens.contains(token)) {
            respond(exchange, 403, "{\"errors\":[\"permission denied\"]}");
            return;
        }
        reads.incrementAndGet();
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
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
