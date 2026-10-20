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

package org.apache.zookeeper.server.jersey.filters;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.zookeeper.server.auth.AuthorizationHeader;
import org.apache.zookeeper.server.auth.SpnegoAcceptor;
import org.apache.zookeeper.server.jersey.cfg.Credentials;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP authentication of the REST gateway: SPNEGO (Kerberos) when an
 * acceptor is configured, with HTTP Basic as an optional fallback. A 401
 * response offers every enabled scheme as its own WWW-Authenticate header.
 */
public class HttpAuthFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(HttpAuthFilter.class);

    public static final String REMOTE_USER = "remoteUser";
    public static final String CHALLENGE_HEADER = "WWW-Authenticate";

    private static final String REALM_CHALLENGE = "Basic realm=\"Restricted\"";
    private static final String NEGOTIATE = "Negotiate";
    private static final String BASIC = "Basic";
    // compared against for unknown users too, so a failed lookup takes
    // the constant-time comparison path
    private static final String UNKNOWN_USER_PASSWORD = "not-a-stored-password";

    private final SpnegoAcceptor spnego;
    private final Credentials credentials;

    public HttpAuthFilter(SpnegoAcceptor spnego, Credentials credentials) {
        this.spnego = spnego;
        this.credentials = credentials;
    }

    @Override
    public void doFilter(ServletRequest req0, ServletResponse resp0,
            FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req0;
        HttpServletResponse response = (HttpServletResponse) resp0;

        String authorization = request.getHeader("Authorization");

        if (spnego != null && AuthorizationHeader.isScheme(authorization, NEGOTIATE)) {
            if (negotiate(request, response, authorization)) {
                return;
            }
            chain.doFilter(request, response);
            return;
        }
        if (basic(request, authorization)) {
            chain.doFilter(request, response);
            return;
        }
        refuse(response);
    }

    /**
     * Validates the Negotiate token; returns true when the request is fully
     * handled (answered with 401), false when the chain should continue.
     */
    private boolean negotiate(HttpServletRequest request,
            HttpServletResponse response, String authorization) throws IOException {
        byte[] token = AuthorizationHeader.schemeCredentials(authorization, NEGOTIATE);
        if (token == null) {
            refuse(response);
            return true;
        }

        try {
            SpnegoAcceptor.Result result = spnego.accept(token);
            if (result.established) {
                request.setAttribute(REMOTE_USER, result.principal);
                LOG.debug("Authenticated {} via SPNEGO", result.principal);
                if (result.token != null && result.token.length > 0) {
                    response.setHeader(CHALLENGE_HEADER, NEGOTIATE + " "
                            + Base64.getEncoder().encodeToString(result.token));
                }
                return false;
            }
            // A Kerberos token always establishes in one leg; hand the
            // continuation token back and let the client start over.
            if (result.token != null && result.token.length > 0) {
                response.setHeader(CHALLENGE_HEADER, NEGOTIATE + " "
                        + Base64.getEncoder().encodeToString(result.token));
            } else {
                response.addHeader(CHALLENGE_HEADER, NEGOTIATE);
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return true;
        } catch (GSSException e) {
            LOG.warn("SPNEGO authentication failed: {}", e.getMessage());
            refuse(response);
            return true;
        }
    }

    private boolean basic(HttpServletRequest request, String authorization) {
        if (credentials.isEmpty() || !AuthorizationHeader.isScheme(authorization, BASIC)) {
            return false;
        }
        String[] userPass = parseBasicAuthorization(authorization);
        if (userPass == null) {
            return false;
        }
        String stored = credentials.get(userPass[0]);
        String expected = stored != null ? stored : UNKNOWN_USER_PASSWORD;
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                userPass[1].getBytes(StandardCharsets.UTF_8)) || stored == null) {
            return false;
        }
        request.setAttribute(REMOTE_USER, userPass[0]);
        LOG.debug("Authenticated {} via Basic", userPass[0]);
        return true;
    }

    private void refuse(HttpServletResponse response) throws IOException {
        if (spnego != null) {
            response.addHeader(CHALLENGE_HEADER, NEGOTIATE);
        }
        if (!credentials.isEmpty()) {
            response.addHeader(CHALLENGE_HEADER, REALM_CHALLENGE);
        }
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private static String[] parseBasicAuthorization(String authorization) {
        byte[] decoded = AuthorizationHeader.schemeCredentials(authorization, BASIC);
        if (decoded == null) {
            return null;
        }
        String userPass = new String(decoded, StandardCharsets.UTF_8);
        int p = userPass.indexOf(':');
        if (p < 1 || p == userPass.length() - 1) {
            return null;
        }
        return new String[] {userPass.substring(0, p), userPass.substring(p + 1)};
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {
    }

    @Override
    public void destroy() {
    }
}
