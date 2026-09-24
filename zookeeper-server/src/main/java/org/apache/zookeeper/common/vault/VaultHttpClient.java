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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP client of the Vault KV v2 read API. Transport failures and 5xx or 429 answers are retried
 * at a fixed interval. A 401 or 403 answer to a token Vault still accepts is a policy that denies
 * the path; to any other token it gets one fresh login.
 */
final class VaultHttpClient {

    private static final Logger LOG = LoggerFactory.getLogger(VaultHttpClient.class);

    private static final String TOKEN_HEADER = "X-Vault-Token";
    private static final int TEMPORARY_REDIRECT = 307;
    private static final int PERMANENT_REDIRECT = 308;
    private static final int MAX_REDIRECTS = 3;
    private static final int TOO_MANY_REQUESTS = 429;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final VaultConnectionInfo connInfo;
    private final VaultAuthMethod authMethod;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int retryCount;
    private final int retryIntervalMs;
    private final SSLSocketFactory sslSocketFactory;
    private final Object loginLock = new Object();
    private volatile String clientToken;

    VaultHttpClient(VaultConnectionInfo connInfo, VaultAuthMethod authMethod, int connectTimeoutMs,
                    int readTimeoutMs, int retryCount, int retryIntervalMs, SSLSocketFactory sslSocketFactory) {
        this.connInfo = connInfo;
        this.authMethod = authMethod;
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.retryCount = retryCount;
        this.retryIntervalMs = retryIntervalMs;
        this.sslSocketFactory = sslSocketFactory;
    }

    /**
     * Reads one field of a secret as text.
     *
     * @param dataPath the KV v2 data path
     * @param field the field within the secret
     * @return the field, or null when the secret, its current version or the field does not exist,
     *         or when the policy of the token denies reading it
     * @throws IOException if the request fails or the field is not a scalar
     */
    String readField(String dataPath, String field) throws IOException {
        String url = connInfo.apiUrl(dataPath);
        Response response = execute(url);
        if (response.status == HttpURLConnection.HTTP_NOT_FOUND) {
            checkAbsent(response);
            return null;
        }
        if (response.status == HttpURLConnection.HTTP_UNAUTHORIZED || response.status == HttpURLConnection.HTTP_FORBIDDEN) {
            LOG.info("The Vault policy denies reading {}; treating it as absent", dataPath);
            return null;
        }
        JsonNode value = parse(response.body, url).path("data").path("data").path(field);
        if (value.isMissingNode() || value.isNull()) {
            return null;
        }
        if (!value.isValueNode()) {
            throw new IOException("Field " + field + " of " + dataPath + " is not a string");
        }
        return value.asText();
    }

    /**
     * A KV v2 404 without errors is a secret that does not exist, or whose current version is
     * deleted; with errors, the path is not served by any engine.
     */
    private static void checkAbsent(Response response) throws IOException {
        if (response.body.trim().isEmpty()) {
            return;
        }
        JsonNode errors;
        try {
            errors = MAPPER.readTree(response.body).path("errors");
        } catch (IOException e) {
            throw response.failure();
        }
        if (errors.isArray() && errors.size() > 0) {
            throw response.failure();
        }
    }

    private Response execute(String url) throws IOException {
        String action = "Vault request GET " + url;
        boolean reauthenticated = false;
        IOException lastFailure = null;
        int attempt = 0;
        while (true) {
            String token = clientToken;
            if (token == null) {
                token = login(null);
            }
            Response response = null;
            try {
                response = get(url, token);
            } catch (IOException e) {
                if (!isTransient(e)) {
                    throw e;
                }
                lastFailure = e;
                LOG.warn("{} failed (attempt {}/{}): {}", action, attempt + 1, retryCount + 1, e.getMessage());
            }
            if (response != null) {
                int status = response.status;
                if (status == HttpURLConnection.HTTP_OK || status == HttpURLConnection.HTTP_NOT_FOUND) {
                    return response;
                }
                if (status == HttpURLConnection.HTTP_UNAUTHORIZED || status == HttpURLConnection.HTTP_FORBIDDEN) {
                    if (isAccepted(token)) {
                        return response;
                    }
                    if (reauthenticated) {
                        throw response.failure();
                    }
                    reauthenticated = true;
                    LOG.debug("{} answered {} and the token is no longer valid, logging in again", action, status);
                    login(token);
                    continue;
                }
                RequestFailedException failure = response.failure();
                if (!failure.isTransient()) {
                    throw failure;
                }
                lastFailure = failure;
                LOG.warn("{} failed (attempt {}/{}): {}", action, attempt + 1, retryCount + 1, failure.getMessage());
            }
            if (attempt >= retryCount) {
                throw new IOException(action + " failed after " + (attempt + 1) + " attempts", lastFailure);
            }
            attempt++;
            sleep(retryIntervalMs);
        }
    }

    /**
     * Whether Vault still accepts the token. A token whose policy has no access to
     * {@code auth/token/lookup-self} counts as refused.
     */
    private boolean isAccepted(String token) {
        try {
            return get(connInfo.apiUrl("auth/token/lookup-self"), token).status == HttpURLConnection.HTTP_OK;
        } catch (IOException e) {
            LOG.debug("Vault token lookup failed", e);
            return false;
        }
    }

    /**
     * Logs in, unless another thread already replaced the token that was refused.
     */
    private String login(String refusedToken) throws IOException {
        synchronized (loginLock) {
            if (clientToken == refusedToken) {
                clientToken = authMethod.authenticate(this);
            }
            return clientToken;
        }
    }

    /**
     * Runs a request that is safe to repeat, retrying transient failures.
     */
    <T> T retrying(String action, RetriableCall<T> call) throws IOException {
        IOException lastFailure = null;
        for (int attempt = 0; ; attempt++) {
            if (attempt > 0) {
                sleep(retryIntervalMs);
            }
            try {
                return call.call();
            } catch (IOException e) {
                if (!isTransient(e)) {
                    throw e;
                }
                lastFailure = e;
                LOG.warn("{} failed (attempt {}/{}): {}", action, attempt + 1, retryCount + 1, e.getMessage());
                if (attempt >= retryCount) {
                    throw new IOException(action + " failed after " + (attempt + 1) + " attempts", lastFailure);
                }
            }
        }
    }

    /**
     * A request that may be repeated.
     */
    interface RetriableCall<T> {

        T call() throws IOException;
    }

    /**
     * POSTs a JSON body with the given Authorization header and returns the response body. A
     * redirect, such as a standby node sends, is followed with the header: the JDK would drop it.
     *
     * @throws RequestFailedException if the answer is not 200
     */
    String post(String url, String authorization, String jsonBody) throws IOException {
        URL target = new URL(url);
        for (int redirects = 0; ; redirects++) {
            HttpURLConnection conn = open(target.toString(), "POST");
            conn.setInstanceFollowRedirects(false);
            conn.setRequestProperty("Authorization", authorization);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }
            int status = conn.getResponseCode();
            if (status == HttpURLConnection.HTTP_OK) {
                return readBody(conn.getInputStream());
            }
            String location = conn.getHeaderField("Location");
            if ((status == TEMPORARY_REDIRECT || status == PERMANENT_REDIRECT) && location != null
                && redirects < MAX_REDIRECTS) {
                readBody(conn.getInputStream());
                URL next = new URL(target, location);
                if (!next.getProtocol().equals(target.getProtocol())) {
                    throw new IOException("POST " + target + " was redirected to " + next + " over another protocol");
                }
                LOG.debug("Following the redirect of POST {} to {}", target, next);
                target = next;
                continue;
            }
            throw new RequestFailedException(status,
                "POST " + target + " failed with status " + status + ": " + readBody(conn.getErrorStream()));
        }
    }

    private Response get(String url, String token) throws IOException {
        HttpURLConnection conn = open(url, "GET");
        conn.setRequestProperty(TOKEN_HEADER, token);
        int status = conn.getResponseCode();
        String body = readBody(status >= HttpURLConnection.HTTP_BAD_REQUEST ? conn.getErrorStream() : conn.getInputStream());
        return new Response(url, status, body);
    }

    private HttpURLConnection open(String url, String method) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(connectTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);
        conn.setUseCaches(false);
        if (sslSocketFactory != null && conn instanceof HttpsURLConnection) {
            ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
        }
        return conn;
    }

    private static String readBody(InputStream is) throws IOException {
        if (is == null) {
            return "";
        }
        try (InputStream in = is) {
            return IOUtils.toString(in, StandardCharsets.UTF_8);
        }
    }

    static JsonNode parse(String body, String url) throws IOException {
        try {
            return MAPPER.readTree(body);
        } catch (IOException e) {
            throw new IOException("Vault response from " + url + " is not JSON", e);
        }
    }

    /**
     * A JSON object of alternating keys and values; null values are left out.
     */
    static String json(String... keyValues) {
        ObjectNode node = MAPPER.createObjectNode();
        for (int i = 0; i + 1 < keyValues.length; i += 2) {
            if (keyValues[i + 1] != null) {
                node.put(keyValues[i], keyValues[i + 1]);
            }
        }
        return node.toString();
    }

    private static boolean isTransient(IOException e) {
        return e instanceof SocketException
            || e instanceof SocketTimeoutException
            || e instanceof UnknownHostException
            || (e instanceof RequestFailedException && ((RequestFailedException) e).isTransient());
    }

    private static void sleep(long ms) throws IOException {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while retrying a Vault request", e);
        }
    }

    private static final class Response {

        private final String url;
        private final int status;
        private final String body;

        Response(String url, int status, String body) {
            this.url = url;
            this.status = status;
            this.body = body;
        }

        RequestFailedException failure() {
            return new RequestFailedException(status, "GET " + url + " failed with status " + status + ": " + body);
        }
    }

    /**
     * An answer with a status the caller cannot use.
     */
    static final class RequestFailedException extends IOException {

        private static final long serialVersionUID = 1L;
        private final int status;

        RequestFailedException(int status, String message) {
            super(message);
            this.status = status;
        }

        int getStatus() {
            return status;
        }

        /**
         * Whether a later attempt may succeed: the server is busy or down.
         */
        boolean isTransient() {
            return status >= HttpURLConnection.HTTP_INTERNAL_ERROR || status == TOO_MANY_REQUESTS;
        }
    }
}
