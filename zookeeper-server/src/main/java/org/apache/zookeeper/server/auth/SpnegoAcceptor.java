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

package org.apache.zookeeper.server.auth;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SPNEGO acceptor for a service principal. Logs in from a
 * keytab and validates one Negotiate token per {@link #accept(byte[])}
 * call; a Kerberos token always establishes the context in a single leg, so
 * no state is kept between calls. A failed accept re-logs in from the
 * keytab once per cooldown window and retries, so a rotated service key
 * recovers without a restart.
 */
public class SpnegoAcceptor {

    private static final Logger LOG = LoggerFactory.getLogger(SpnegoAcceptor.class);

    private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";
    private static final String SPNEGO_MECH_OID = "1.3.6.1.5.5.2";
    private static final String KRB5_MECH_OID = "1.2.840.113554.1.2.2";
    private static final String KRB5_PRINCIPAL_NAME_OID = "1.2.840.113554.1.2.2.1";

    private final String principal;
    private final String keytab;

    private volatile Login current;
    private volatile long lastReloginAt;

    /** How often a failing accept may trigger a keytab re-login. */
    long reloginCooldownMs = 30000;

    /** Subject and acceptor credential of one keytab login. */
    static final class Login {

        final Subject subject;
        final GSSCredential credential;

        Login(Subject subject, GSSCredential credential) {
            this.subject = subject;
            this.credential = credential;
        }
    }

    SpnegoAcceptor(String principal, String keytab, Login initial) {
        this.principal = principal;
        this.keytab = keytab;
        this.current = initial;
    }

    public static SpnegoAcceptor create(String principal, String keytab) throws IOException {
        SpnegoAcceptor acceptor = new SpnegoAcceptor(principal, keytab, null);
        acceptor.current = acceptor.doLogin();
        LOG.info("SPNEGO acceptor ready for principal {}", principal);
        return acceptor;
    }

    /** Performs one keytab login as the service principal. */
    Login doLogin() throws IOException {
        try {
            LoginContext login = new LoginContext("zk-rest-spnego", null, null,
                    keytabConfiguration(principal, keytab));
            login.login();
            Subject subject = login.getSubject();
            GSSManager manager = GSSManager.getInstance();
            GSSCredential credential = Subject.doAs(subject,
                    (PrivilegedExceptionAction<GSSCredential>) () -> manager.createCredential(
                            manager.createName(principal, new Oid(KRB5_PRINCIPAL_NAME_OID)),
                            GSSCredential.INDEFINITE_LIFETIME,
                            new Oid[] {new Oid(SPNEGO_MECH_OID), new Oid(KRB5_MECH_OID)},
                            GSSCredential.ACCEPT_ONLY));
            return new Login(subject, credential);
        } catch (LoginException | PrivilegedActionException e) {
            throw new IOException("SPNEGO acceptor login as " + principal
                    + " from keytab " + keytab + " failed", e);
        }
    }

    private static Configuration keytabConfiguration(String principal, String keytab) {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, Object> options = new HashMap<>();
                options.put("useKeyTab", "true");
                options.put("keyTab", keytab);
                options.put("principal", principal);
                options.put("storeKey", "true");
                options.put("useTicketCache", "false");
                options.put("doNotPrompt", "true");
                options.put("refreshKrb5Config", "true");
                options.put("isInitiator", "false");
                return new AppConfigurationEntry[] {new AppConfigurationEntry(
                        KRB5_LOGIN_MODULE,
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        options)};
            }
        };
    }

    /**
     * Validates one Negotiate token. On success the principal the token
     * authenticates and the response token for the client (the AP-REP when
     * the client asked for mutual authentication) are returned.
     */
    public Result accept(byte[] token) throws GSSException {
        try {
            return accept(current, token);
        } catch (GSSException failure) {
            if (!reloginAfterFailure()) {
                throw failure;
            }
            return accept(current, token);
        }
    }

    /** One accept attempt against the given login. */
    Result accept(Login login, byte[] token) throws GSSException {
        try {
            return Subject.doAs(login.subject, (PrivilegedExceptionAction<Result>) () -> {
                GSSContext context = GSSManager.getInstance()
                        .createContext(login.credential);
                try {
                    byte[] outToken = context.acceptSecContext(token, 0, token.length);
                    boolean established = context.isEstablished();
                    String principal = established ? context.getSrcName().toString() : null;
                    return new Result(established, principal, outToken);
                } finally {
                    context.dispose();
                }
            });
        } catch (PrivilegedActionException e) {
            Exception cause = e.getException();
            if (cause instanceof GSSException) {
                throw (GSSException) cause;
            }
            GSSException failure = new GSSException(GSSException.FAILURE, 0,
                    cause.getMessage());
            failure.initCause(cause);
            throw failure;
        }
    }

    private synchronized boolean reloginAfterFailure() {
        long now = System.currentTimeMillis();
        if (now - lastReloginAt < reloginCooldownMs) {
            return false;
        }
        lastReloginAt = now;
        try {
            current = doLogin();
            LOG.warn("SPNEGO acceptor re-logged in as {} from {} after an accept failure",
                    principal, keytab);
            return true;
        } catch (IOException e) {
            LOG.error("SPNEGO acceptor re-login as {} from {} failed: {}",
                    principal, keytab, e.getMessage());
            return false;
        }
    }

    public static final class Result {

        public final boolean established;
        public final String principal;
        public final byte[] token;

        public Result(boolean established, String principal, byte[] token) {
            this.established = established;
            this.principal = principal;
            this.token = token;
        }
    }
}
