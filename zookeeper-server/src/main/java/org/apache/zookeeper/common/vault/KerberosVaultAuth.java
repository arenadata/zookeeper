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
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.Locale;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Login to the Vault Kerberos auth method over SPNEGO, as the principal of a JAAS login context.
 * Each login authenticates to the KDC afresh, so no ticket has to be renewed in between. The
 * token travels in the Authorization header, which the auth mount must pass through
 * ({@code passthrough_request_headers}).
 */
final class KerberosVaultAuth implements VaultAuthMethod {

    private static final Logger LOG = LoggerFactory.getLogger(KerberosVaultAuth.class);

    private static final String SPNEGO_MECH_OID = "1.3.6.1.5.5.2";
    private static final String KRB5_PRINCIPAL_NAME_OID = "1.2.840.113554.1.2.2.1";
    private static final String HOSTNAME_PATTERN = "_HOST";

    private final String loginContext;
    private final String servicePrincipal;
    private final String loginUrl;
    private final String role;

    /**
     * Creates the login of a JAAS section.
     *
     * @param connInfo the Vault server
     * @param loginContext the JAAS section to log in with
     * @param servicePrincipal the Vault service principal; {@code _HOST} stands for the Vault host
     *                         in lower case, null means {@code HTTP@<Vault host>}
     * @param mountPath the mount path of the Kerberos auth method
     * @param role the role to log in with, or null to let Vault pick the one bound to the principal
     */
    KerberosVaultAuth(VaultConnectionInfo connInfo, String loginContext, String servicePrincipal, String mountPath,
                      String role) throws IOException {
        this.loginContext = loginContext;
        String host = connInfo.getHost().toLowerCase(Locale.ROOT);
        this.servicePrincipal = servicePrincipal == null ? "HTTP@" + host : servicePrincipal.replace(HOSTNAME_PATTERN, host);
        String mount = VaultConnectionInfo.stripSlashes(mountPath);
        VaultConnectionInfo.checkPath(mount);
        this.loginUrl = connInfo.apiUrl(mount + "/login");
        this.role = role;
    }

    @Override
    public String authenticate(VaultHttpClient client) throws IOException {
        String body = VaultHttpClient.json("role", role);
        String response = client.retrying("Vault Kerberos login to " + loginUrl,
            () -> client.post(loginUrl, "Negotiate " + spnegoToken(), body));
        JsonNode token = VaultHttpClient.parse(response, loginUrl).path("auth").path("client_token");
        if (!token.isTextual() || token.asText().isEmpty()) {
            throw new IOException("Vault login response from " + loginUrl + " has no auth.client_token");
        }
        LOG.info("Logged in to {} with JAAS section {}", loginUrl, loginContext);
        return token.asText();
    }

    private String spnegoToken() throws IOException {
        LoginContext lc;
        try {
            lc = new LoginContext(loginContext);
            lc.login();
        } catch (LoginException | SecurityException e) {
            throw new IOException("Kerberos login with JAAS section " + loginContext + " failed", e);
        }
        try {
            return Subject.doAs(lc.getSubject(), (PrivilegedExceptionAction<String>) this::initSecContext);
        } catch (PrivilegedActionException e) {
            throw new IOException("Failed to create a SPNEGO token for " + servicePrincipal, e.getException());
        } finally {
            try {
                lc.logout();
            } catch (LoginException e) {
                LOG.debug("Logout of JAAS section {} failed", loginContext, e);
            }
        }
    }

    private String initSecContext() throws GSSException {
        GSSManager manager = GSSManager.getInstance();
        Oid nameType = servicePrincipal.contains("/") ? new Oid(KRB5_PRINCIPAL_NAME_OID) : GSSName.NT_HOSTBASED_SERVICE;
        GSSName serverName = manager.createName(servicePrincipal, nameType);
        GSSContext context = manager.createContext(serverName, new Oid(SPNEGO_MECH_OID), null,
            GSSContext.DEFAULT_LIFETIME);
        try {
            context.requestMutualAuth(true);
            context.requestCredDeleg(false);
            byte[] token = context.initSecContext(new byte[0], 0, 0);
            return Base64.getEncoder().encodeToString(token);
        } finally {
            context.dispose();
        }
    }
}
