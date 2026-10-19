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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Base64;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.zookeeper.server.jersey.cfg.Credentials;
import org.ietf.jgss.GSSException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

public class HttpAuthFilterTest {

    private static final String REALM_CHALLENGE = "Basic realm=\"Restricted\"";

    private SpnegoAcceptor spnego;
    private Credentials credentials;
    private HttpAuthFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;

    @BeforeEach
    public void setUp() {
        spnego = mock(SpnegoAcceptor.class);
        credentials = new Credentials();
        credentials.put("probe", "secret");
        filter = new HttpAuthFilter(spnego, credentials);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
    }

    private void run() throws IOException, ServletException {
        filter.doFilter(request, response, chain);
    }

    private void givenNoAuthorization() {
        when(request.getHeader("Authorization")).thenReturn(null);
    }

    private void givenAuthorization(String value) {
        when(request.getHeader("Authorization")).thenReturn(value);
    }

    private String authenticatedUser() {
        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(request).setAttribute(eq(HttpAuthFilter.REMOTE_USER), captor.capture());
        return (String) captor.getValue();
    }

    @Test
    public void testMissingAuthorizationChallengesWithNegotiateAndBasic() throws Exception {
        givenNoAuthorization();
        run();
        verify(response).addHeader(HttpAuthFilter.CHALLENGE_HEADER, "Negotiate");
        verify(response).addHeader(HttpAuthFilter.CHALLENGE_HEADER, REALM_CHALLENGE);
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testMissingAuthorizationChallengesWithBasicOnlyWithoutSpnego() throws Exception {
        filter = new HttpAuthFilter(null, credentials);
        givenNoAuthorization();
        run();
        verify(response).addHeader(HttpAuthFilter.CHALLENGE_HEADER, REALM_CHALLENGE);
        verify(response, never()).addHeader(HttpAuthFilter.CHALLENGE_HEADER, "Negotiate");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testMissingAuthorizationChallengesWithNegotiateOnlyWithoutBasic() throws Exception {
        filter = new HttpAuthFilter(spnego, new Credentials());
        givenNoAuthorization();
        run();
        verify(response).addHeader(HttpAuthFilter.CHALLENGE_HEADER, "Negotiate");
        verify(response, never()).addHeader(HttpAuthFilter.CHALLENGE_HEADER, REALM_CHALLENGE);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testBasicCredentialsPass() throws Exception {
        givenAuthorization("Basic "
                + Base64.getEncoder().encodeToString("probe:secret".getBytes()));
        run();
        verify(chain).doFilter(request, response);
        assertEquals("probe", authenticatedUser());
        verify(response, never()).sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void testWrongBasicPasswordIsRefused() throws Exception {
        givenAuthorization("Basic "
                + Base64.getEncoder().encodeToString("probe:wrong".getBytes()));
        run();
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testUnknownBasicUserIsRefused() throws Exception {
        givenAuthorization("Basic "
                + Base64.getEncoder().encodeToString("nobody:secret".getBytes()));
        run();
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testNegotiateTokenAuthenticatesTheClientPrincipal() throws Exception {
        byte[] apRep = {1, 2, 3};
        when(spnego.accept(any())).thenReturn(
                new SpnegoAcceptor.Result(true, "client@REALM", apRep));
        givenAuthorization("Negotiate "
                + Base64.getEncoder().encodeToString(new byte[] {9, 9}));
        run();
        verify(chain).doFilter(request, response);
        assertEquals("client@REALM", authenticatedUser());
        verify(response).setHeader(HttpAuthFilter.CHALLENGE_HEADER,
                "Negotiate " + Base64.getEncoder().encodeToString(apRep));
    }

    @Test
    public void testFailedNegotiateTokenIsRefused() throws Exception {
        when(spnego.accept(any())).thenThrow(new GSSException(GSSException.DEFECTIVE_TOKEN));
        givenAuthorization("Negotiate "
                + Base64.getEncoder().encodeToString(new byte[] {9, 9}));
        run();
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response).addHeader(HttpAuthFilter.CHALLENGE_HEADER, "Negotiate");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testTokenThatIsNotBase64IsRefused() throws Exception {
        givenAuthorization("Negotiate ???");
        run();
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testUnestablishedTokenAsksTheClientToContinue() throws Exception {
        byte[] continueToken = {7, 7};
        when(spnego.accept(any())).thenReturn(
                new SpnegoAcceptor.Result(false, null, continueToken));
        givenAuthorization("Negotiate "
                + Base64.getEncoder().encodeToString(new byte[] {9, 9}));
        run();
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response).setHeader(HttpAuthFilter.CHALLENGE_HEADER,
                "Negotiate " + Base64.getEncoder().encodeToString(continueToken));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testUnestablishedTokenWithoutResponseTokenIsRefused() throws Exception {
        when(spnego.accept(any())).thenReturn(
                new SpnegoAcceptor.Result(false, null, null));
        givenAuthorization("Negotiate "
                + Base64.getEncoder().encodeToString(new byte[] {9, 9}));
        run();
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response).addHeader(HttpAuthFilter.CHALLENGE_HEADER, "Negotiate");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testLowercaseNegotiateSchemeIsAccepted() throws Exception {
        when(spnego.accept(any())).thenReturn(
                new SpnegoAcceptor.Result(true, "client@REALM", null));
        givenAuthorization("negotiate "
                + Base64.getEncoder().encodeToString(new byte[] {9, 9}));
        run();
        verify(chain).doFilter(request, response);
        assertEquals("client@REALM", authenticatedUser());
    }

    @Test
    public void testLowercaseBasicSchemeIsAccepted() throws Exception {
        givenAuthorization("basic "
                + Base64.getEncoder().encodeToString("probe:secret".getBytes()));
        run();
        verify(chain).doFilter(request, response);
    }

    @Test
    public void testNegotiateWithoutSpnegoConfiguredIsRefused() throws Exception {
        filter = new HttpAuthFilter(null, credentials);
        givenAuthorization("Negotiate "
                + Base64.getEncoder().encodeToString(new byte[] {9, 9}));
        run();
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        verify(chain, never()).doFilter(any(), any());
    }
}
