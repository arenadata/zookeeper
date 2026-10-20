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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.io.IOException;
import org.ietf.jgss.GSSException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The re-login policy of the acceptor: a failed accept must pick up a fresh
 * keytab login (keytab rollover), a failed re-login must surface the
 * original error, and the cooldown must keep a failing client from causing
 * a re-login per request.
 */
public class SpnegoAcceptorReloginTest {

    private SpnegoAcceptor.Login initialLogin;
    private SpnegoAcceptor.Login reloadedLogin;
    private IOException loginFailure;
    private int logins;
    private int attempts;
    private SpnegoAcceptor.Login acceptedBy;

    @BeforeEach
    public void setUp() {
        initialLogin = new SpnegoAcceptor.Login(null, null);
        reloadedLogin = new SpnegoAcceptor.Login(null, null);
    }

    /** Accepts only with a login fresh from the keytab, like a rotated kvno. */
    private SpnegoAcceptor acceptor() {
        return new SpnegoAcceptor("HTTP/host@REALM", "/etc/keytab", initialLogin) {
            @Override
            SpnegoAcceptor.Login doLogin() throws IOException {
                logins++;
                if (loginFailure != null) {
                    throw loginFailure;
                }
                return reloadedLogin;
            }

            @Override
            SpnegoAcceptor.Result accept(SpnegoAcceptor.Login login, byte[] token)
                    throws GSSException {
                attempts++;
                acceptedBy = login;
                if (login == initialLogin) {
                    throw new GSSException(GSSException.DEFECTIVE_TOKEN);
                }
                return new SpnegoAcceptor.Result(true, "client@REALM", null);
            }
        };
    }

    @Test
    public void testFailedAcceptPicksUpAFreshLogin() throws Exception {
        SpnegoAcceptor.Result result = acceptor().accept(new byte[] {1});
        assertEquals("client@REALM", result.principal);
        assertEquals(1, logins);
        assertEquals(2, attempts);
        assertSame(reloadedLogin, acceptedBy);
    }

    @Test
    public void testFailedReloginSurfacesTheOriginalFailure() {
        loginFailure = new IOException("keytab gone");
        GSSException e = assertThrows(GSSException.class,
                () -> acceptor().accept(new byte[] {1}));
        assertEquals(GSSException.DEFECTIVE_TOKEN, e.getMajor());
        assertEquals(1, logins);
        assertEquals(1, attempts);
    }

    @Test
    public void testCooldownKeepsAFailingClientFromReloggingInPerRequest() {
        SpnegoAcceptor acceptor = acceptor();
        loginFailure = new IOException("keytab gone");
        assertThrows(GSSException.class, () -> acceptor.accept(new byte[] {1}));
        loginFailure = null;
        // the keytab works again, but the cooldown window is still open
        assertThrows(GSSException.class, () -> acceptor.accept(new byte[] {1}));
        assertEquals(1, logins);
        assertEquals(2, attempts);
    }
}
