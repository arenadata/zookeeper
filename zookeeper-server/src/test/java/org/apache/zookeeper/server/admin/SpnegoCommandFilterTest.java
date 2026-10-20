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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Base64;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.zookeeper.server.auth.SpnegoAcceptor;
import org.ietf.jgss.GSSException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SpnegoCommandFilterTest {

    private SpnegoAcceptor acceptor;
    private SpnegoCommandFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;
    private StringWriter body;

    @BeforeEach
    public void setUp() throws Exception {
        acceptor = mock(SpnegoAcceptor.class);
        filter = new SpnegoCommandFilter(
            acceptor,
            SpnegoCommandFilter.parseCommands(SpnegoCommandFilter.DEFAULT_COMMANDS),
            "/commands");
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        body = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(body));
        when(request.getContextPath()).thenReturn("");
        System.clearProperty("zookeeper.admin.spnego.principal");
        System.clearProperty("zookeeper.admin.spnego.keytab");
    }

    @AfterEach
    public void tearDown() {
        System.clearProperty("zookeeper.admin.spnego.principal");
        System.clearProperty("zookeeper.admin.spnego.keytab");
    }

    private void stubUri(String uri) {
        when(request.getRequestURI()).thenReturn(uri);
    }

    private void stubValidToken() throws GSSException {
        when(request.getHeader("Authorization")).thenReturn("Negotiate "
                + Base64.getEncoder().encodeToString(new byte[]{1}));
        when(acceptor.accept(any())).thenReturn(
            new SpnegoAcceptor.Result(true, "user@REALM", null));
    }

    @Test
    public void testUnauthenticatedRequestGets401EvenForBlockedCommand() throws Exception {
        stubUri("/commands/srst");
        when(request.getHeader("Authorization")).thenReturn(null);

        filter.doFilter(request, response, chain);

        verify(response).setStatus(401);
        verify(response).setHeader("WWW-Authenticate", "Negotiate");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testNeverCommandBlockedForAuthenticatedUser() throws Exception {
        stubUri("/commands/srst");
        stubValidToken();

        filter.doFilter(request, response, chain);

        verify(response).setStatus(403);
        verify(response).setContentType("application/json");
        assertTrue(body.toString().contains("srst is not allowed"));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testCommandOutsideAllowlistBlocked() throws Exception {
        stubUri("/commands/cons");
        stubValidToken();

        filter.doFilter(request, response, chain);

        verify(response).setStatus(403);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testAllowedCommandPassesWithPrincipalAttribute() throws Exception {
        stubUri("/commands/mntr");
        stubValidToken();

        filter.doFilter(request, response, chain);

        verify(request).setAttribute(SpnegoCommandFilter.REMOTE_PRINCIPAL, "user@REALM");
        verify(chain).doFilter(request, response);
        verify(response, never()).setStatus(anyIntValue());
    }

    @Test
    public void testMutualAuthTokenReturnedAsHeader() throws Exception {
        stubUri("/commands/mntr");
        when(request.getHeader("Authorization")).thenReturn("Negotiate "
                + Base64.getEncoder().encodeToString(new byte[]{1}));
        when(acceptor.accept(any())).thenReturn(
            new SpnegoAcceptor.Result(true, "user@REALM", new byte[]{2, 3}));

        filter.doFilter(request, response, chain);

        verify(response).setHeader("WWW-Authenticate",
            "Negotiate " + Base64.getEncoder().encodeToString(new byte[]{2, 3}));
        verify(chain).doFilter(request, response);
    }

    @Test
    public void testGarbageTokenRefused() throws Exception {
        stubUri("/commands/mntr");
        when(request.getHeader("Authorization")).thenReturn("Negotiate !!!not-base64!!!");

        filter.doFilter(request, response, chain);

        verify(response).setStatus(401);
        verify(response).setHeader("WWW-Authenticate", "Negotiate");
        verify(acceptor, never()).accept(any());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testGssFailureRefused() throws Exception {
        stubUri("/commands/mntr");
        when(request.getHeader("Authorization")).thenReturn("Negotiate "
                + Base64.getEncoder().encodeToString(new byte[]{1}));
        when(acceptor.accept(any())).thenThrow(new GSSException(GSSException.FAILURE));

        filter.doFilter(request, response, chain);

        verify(response).setStatus(401);
        verify(response).setHeader("WWW-Authenticate", "Negotiate");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testUnestablishedContextRefused() throws Exception {
        stubUri("/commands/mntr");
        when(request.getHeader("Authorization")).thenReturn("Negotiate "
                + Base64.getEncoder().encodeToString(new byte[]{1}));
        when(acceptor.accept(any())).thenReturn(
            new SpnegoAcceptor.Result(false, null, null));

        filter.doFilter(request, response, chain);

        verify(response).setStatus(401);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testParseCommands() {
        assertTrue(SpnegoCommandFilter.parseCommands(
            SpnegoCommandFilter.DEFAULT_COMMANDS).contains("mntr"));
        assertFalse(SpnegoCommandFilter.parseCommands(
            SpnegoCommandFilter.DEFAULT_COMMANDS).contains("cons"));
        assertTrue(SpnegoCommandFilter.parseCommands("*").contains("*"));
        assertEquals(3, SpnegoCommandFilter.parseCommands("a, b,,c").size());
    }

    @Test
    public void testEncodedNeverCommandBlockedUnderWildcardAllowlist() throws Exception {
        SpnegoCommandFilter wildcard = new SpnegoCommandFilter(
            acceptor, SpnegoCommandFilter.parseCommands("*"), "/commands");
        when(request.getRequestURI()).thenReturn("/commands/s%72st");
        stubValidToken();

        wildcard.doFilter(request, response, chain);

        // the servlet decodes s%72st to srst, so the filter must not pass it on
        verify(response).setStatus(403);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    public void testLowercaseSchemeAccepted() throws Exception {
        stubUri("/commands/mntr");
        when(request.getHeader("Authorization")).thenReturn("negotiate "
                + Base64.getEncoder().encodeToString(new byte[]{1}));
        when(acceptor.accept(any())).thenReturn(
            new SpnegoAcceptor.Result(true, "user@REALM", null));

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    public void testExtraWhitespaceBeforeTokenAccepted() throws Exception {
        stubUri("/commands/mntr");
        when(request.getHeader("Authorization")).thenReturn("Negotiate  "
                + Base64.getEncoder().encodeToString(new byte[]{1}));
        when(acceptor.accept(any())).thenReturn(
            new SpnegoAcceptor.Result(true, "user@REALM", null));

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    public void testCommandNameWithCustomCommandUrl() {
        SpnegoCommandFilter custom = new SpnegoCommandFilter(
            acceptor, SpnegoCommandFilter.parseCommands("*"), "/adm");
        when(request.getRequestURI()).thenReturn("/adm/mntr");
        assertEquals("mntr", custom.commandName(request));
        when(request.getRequestURI()).thenReturn("/adm");
        assertNull(custom.commandName(request));
        when(request.getRequestURI()).thenReturn("/adm/");
        assertNull(custom.commandName(request));
    }

    @Test
    public void testCreateIfConfiguredWithoutKeysReturnsNull() throws Exception {
        assertNull(SpnegoCommandFilter.createIfConfigured("/commands"));
    }

    @Test
    public void testCreateIfConfiguredRejectsPrincipalWithoutKeytab() {
        System.setProperty("zookeeper.admin.spnego.principal", "HTTP/localhost@REALM");
        assertThrows(IOException.class, () -> SpnegoCommandFilter.createIfConfigured("/commands"));
    }

    @Test
    public void testCreateIfConfiguredRejectsMissingKeytabFile() {
        System.setProperty("zookeeper.admin.spnego.principal", "HTTP/localhost@REALM");
        System.setProperty("zookeeper.admin.spnego.keytab", "/nonexistent/http.keytab");
        assertThrows(IOException.class, () -> SpnegoCommandFilter.createIfConfigured("/commands"));
    }

    private static int anyIntValue() {
        return org.mockito.ArgumentMatchers.anyInt();
    }
}
