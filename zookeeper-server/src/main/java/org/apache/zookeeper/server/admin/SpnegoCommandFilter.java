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

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.zookeeper.common.vault.KerberosVaultAuth;
import org.apache.zookeeper.server.auth.SpnegoAcceptor;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SPNEGO authentication for the admin server's command URLs. The Negotiate
 * token is validated before any command-name check, so an unauthenticated
 * request learns nothing about which commands are configured.
 */
public class SpnegoCommandFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(SpnegoCommandFilter.class);

    /** Mutating commands are never served through this filter, by primary name and alias. */
    static final Set<String> NEVER = new HashSet<>(Arrays.asList(
        "stat_reset",
        "srst",
        "connection_stat_reset",
        "crst",
        "observer_connection_stat_reset",
        "orst",
        "set_trace_mask",
        "stmk",
        "snapshot",
        "snap",
        "restore",
        "rest"));

    static final String DEFAULT_COMMANDS = "ruok,srvr,stat,mntr,conf,isro,wchs,dirs";

    public static final String REMOTE_PRINCIPAL = "remotePrincipal";

    private static final String PRINCIPAL_KEY = "zookeeper.admin.spnego.principal";
    private static final String KEYTAB_KEY = "zookeeper.admin.spnego.keytab";
    private static final String COMMANDS_KEY = "zookeeper.admin.spnego.commands";
    private static final String NEGOTIATE = "Negotiate";

    private final SpnegoAcceptor acceptor;
    private final Set<String> allowedCommands;
    private final String commandUrl;

    SpnegoCommandFilter(SpnegoAcceptor acceptor, Set<String> allowedCommands, String commandUrl) {
        this.acceptor = acceptor;
        this.allowedCommands = allowedCommands;
        this.commandUrl = commandUrl;
    }

    /**
     * Returns a filter for the configured SPNEGO keys, or null when SPNEGO
     * is not configured at all. A half-configured principal/keytab pair, or
     * a keytab the acceptor cannot log in from, fails server startup.
     */
    public static SpnegoCommandFilter createIfConfigured(String commandUrl) throws IOException {
        String principal = System.getProperty(PRINCIPAL_KEY);
        String keytab = System.getProperty(KEYTAB_KEY);
        if (principal == null && keytab == null) {
            return null;
        }
        if (principal == null || keytab == null) {
            throw new IOException(String.format(
                "Both %s and %s must be set to enable admin server SPNEGO",
                PRINCIPAL_KEY, KEYTAB_KEY));
        }
        // the keytab login itself is lazy about a missing file, so check it here
        File keytabFile = new File(keytab);
        if (!keytabFile.isFile() || !keytabFile.canRead()) {
            throw new IOException(
                "Admin server SPNEGO keytab " + keytab + " does not exist or is not readable");
        }
        principal = KerberosVaultAuth.replaceHost(principal,
            InetAddress.getLocalHost().getCanonicalHostName().toLowerCase(Locale.ROOT));
        SpnegoAcceptor acceptor = SpnegoAcceptor.create(principal, keytab);
        Set<String> allowed = parseCommands(System.getProperty(COMMANDS_KEY, DEFAULT_COMMANDS));
        return new SpnegoCommandFilter(acceptor, allowed, commandUrl);
    }

    static Set<String> parseCommands(String value) {
        Set<String> commands = new HashSet<>();
        for (String command : value.split(",")) {
            command = command.trim();
            if (!command.isEmpty()) {
                commands.add(command);
            }
        }
        return commands;
    }

    /** Command name carried by the request, or null for the index page. */
    String commandName(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if (!path.startsWith(commandUrl)) {
            return null;
        }
        String rest = path.substring(commandUrl.length());
        if (rest.isEmpty() || rest.equals("/")) {
            return null;
        }
        return rest.startsWith("/") ? rest.substring(1) : rest;
    }

    @Override
    public void doFilter(ServletRequest request0, ServletResponse response0, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) request0;
        HttpServletResponse response = (HttpServletResponse) response0;
        if (!authenticate(request, response)) {
            return;
        }
        String command = commandName(request);
        if (command != null && !commandAllowed(command)) {
            response.setStatus(403);
            response.setContentType("application/json");
            response.getWriter().println("{\"error\":\"" + command + " is not allowed\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean authenticate(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(NEGOTIATE + " ")) {
            return challenge(response);
        }
        byte[] token;
        try {
            token = Base64.getDecoder().decode(header.substring(NEGOTIATE.length() + 1));
        } catch (IllegalArgumentException e) {
            return challenge(response);
        }
        SpnegoAcceptor.Result result;
        try {
            result = acceptor.accept(token);
        } catch (GSSException e) {
            return challenge(response);
        }
        if (result.token != null && result.token.length > 0) {
            response.setHeader("WWW-Authenticate",
                NEGOTIATE + " " + Base64.getEncoder().encodeToString(result.token));
        }
        if (!result.established) {
            return challenge(response);
        }
        LOG.info("Admin server command request authenticated as {}", result.principal);
        request.setAttribute(REMOTE_PRINCIPAL, result.principal);
        return true;
    }

    private boolean challenge(HttpServletResponse response) {
        response.setHeader("WWW-Authenticate", NEGOTIATE);
        response.setStatus(401);
        return false;
    }

    private boolean commandAllowed(String command) {
        if (NEVER.contains(command)) {
            return false;
        }
        return allowedCommands.contains("*") || allowedCommands.contains(command);
    }

    @Override
    public void init(FilterConfig config) {
    }

    @Override
    public void destroy() {
    }
}
