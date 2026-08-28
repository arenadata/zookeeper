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

package org.apache.zookeeper.server.auth;

import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;
import org.apache.zookeeper.server.token.DelegationTokenIdentifier;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SaslServerCallbackHandler implements CallbackHandler {

    private static final Logger LOG = LoggerFactory.getLogger(SaslServerCallbackHandler.class);
    private static final String SYSPROP_SUPER_PASSWORD = "zookeeper.SASLAuthenticationProvider.superPassword";
    private static final String SYSPROP_REMOVE_HOST = "zookeeper.kerberos.removeHostFromPrincipal";
    private static final String SYSPROP_REMOVE_REALM = "zookeeper.kerberos.removeRealmFromPrincipal";

    private String userName;
    private final Map<String, String> credentials;
    private final DelegationTokenSecretManager tokenManager;
    private DelegationTokenIdentifier tokenIdentifier;

    public SaslServerCallbackHandler(Map<String, String> credentials) {
        this(credentials, null);
    }

    public SaslServerCallbackHandler(Map<String, String> credentials, DelegationTokenSecretManager tokenManager) {
        this.credentials = credentials;
        this.tokenManager = tokenManager;
    }

    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                handleNameCallback((NameCallback) callback);
            } else if (callback instanceof PasswordCallback) {
                handlePasswordCallback((PasswordCallback) callback);
            } else if (callback instanceof RealmCallback) {
                handleRealmCallback((RealmCallback) callback);
            } else if (callback instanceof AuthorizeCallback) {
                handleAuthorizeCallback((AuthorizeCallback) callback);
            }
        }
    }

    private void handleNameCallback(NameCallback nc) {
        tokenIdentifier = null;
        // a delegation token client sends base64(identifier) as the username;
        // anything that does not strictly parse falls back to the static user map.
        if (tokenManager != null) {
            DelegationTokenIdentifier ident = tryParseToken(nc.getDefaultName());
            if (ident != null) {
                try {
                    tokenManager.validate(ident);
                } catch (SaslException e) {
                    LOG.warn("Rejecting delegation token: {}", e.getMessage());
                    return;
                }
                tokenIdentifier = ident;
                nc.setName(nc.getDefaultName());
                userName = nc.getDefaultName();
                return;
            }
        }
        // check to see if this user is in the user password database.
        if (credentials.get(nc.getDefaultName()) == null) {
            LOG.warn("User '{}' not found in list of DIGEST-MD5 authenticateable users.", nc.getDefaultName());
            return;
        }
        nc.setName(nc.getDefaultName());
        userName = nc.getDefaultName();
    }

    /**
     * Returns whether the last handled authentication was a delegation token.
     */
    public boolean isTokenAuthenticated() {
        return tokenIdentifier != null;
    }

    private DelegationTokenIdentifier tryParseToken(String name) {
        if (name == null || name.isEmpty()) {
            return null;
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(name);
        } catch (IllegalArgumentException e) {
            return null;
        }
        try {
            return DelegationTokenIdentifier.fromBytes(decoded);
        } catch (IOException e) {
            return null;
        }
    }

    private void handlePasswordCallback(PasswordCallback pc) {
        if (tokenIdentifier != null) {
            byte[] password = tokenManager.computePassword(tokenIdentifier.toBytes());
            pc.setPassword(Base64.getEncoder().encodeToString(password).toCharArray());
        } else if ("super".equals(this.userName) && System.getProperty(SYSPROP_SUPER_PASSWORD) != null) {
            // superuser: use Java system property for password, if available.
            pc.setPassword(System.getProperty(SYSPROP_SUPER_PASSWORD).toCharArray());
        } else if (credentials.containsKey(userName)) {
            pc.setPassword(credentials.get(userName).toCharArray());
        } else {
            LOG.warn("No password found for user: {}", userName);
        }
    }

    private void handleRealmCallback(RealmCallback rc) {
        LOG.debug("client supplied realm: {}", rc.getDefaultText());
        rc.setText(rc.getDefaultText());
    }

    private void handleAuthorizeCallback(AuthorizeCallback ac) {
        String authenticationID = ac.getAuthenticationID();
        String authorizationID = ac.getAuthorizationID();

        LOG.info("Successfully authenticated client: authenticationID={};  authorizationID={}.",
                 authenticationID, authorizationID);
        ac.setAuthorized(true);

        // a token client authenticates as base64(identifier); authorize it as the token owner
        String principal = tokenIdentifier != null ? tokenIdentifier.getOwner() : authenticationID;

        // canonicalize authorization id according to system properties:
        // zookeeper.kerberos.removeRealmFromPrincipal(={true,false})
        // zookeeper.kerberos.removeHostFromPrincipal(={true,false})
        KerberosName kerberosName = new KerberosName(principal);
        try {
            StringBuilder userNameBuilder = new StringBuilder(kerberosName.getShortName());
            if (shouldAppendHost(kerberosName)) {
                userNameBuilder.append("/").append(kerberosName.getHostName());
            }
            if (shouldAppendRealm(kerberosName)) {
                userNameBuilder.append("@").append(kerberosName.getRealm());
            }
            LOG.info("Setting authorizedID: {}", userNameBuilder);
            ac.setAuthorizedID(userNameBuilder.toString());
        } catch (IOException e) {
            LOG.error("Failed to set name based on Kerberos authentication rules.", e);
            if (tokenIdentifier != null) {
                // without Kerberos rules the token owner is authorized verbatim
                ac.setAuthorizedID(principal);
            }
        }
    }

    private boolean shouldAppendRealm(KerberosName kerberosName) {
        return !isSystemPropertyTrue(SYSPROP_REMOVE_REALM) && kerberosName.getRealm() != null;
    }

    private boolean shouldAppendHost(KerberosName kerberosName) {
        return !isSystemPropertyTrue(SYSPROP_REMOVE_HOST) && kerberosName.getHostName() != null;
    }

    private boolean isSystemPropertyTrue(String propertyName) {
        return "true".equals(System.getProperty(propertyName));
    }

}
