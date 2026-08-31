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

package org.apache.zookeeper.server;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import org.apache.zookeeper.Login;
import org.apache.zookeeper.server.auth.SaslServerCallbackHandler;
import org.apache.zookeeper.util.SecurityUtils;
import org.apache.zookeeper.util.scram.ScramSaslServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ZooKeeperSaslServer {

    public static final String LOGIN_CONTEXT_NAME_KEY = "zookeeper.sasl.serverconfig";
    public static final String DEFAULT_LOGIN_CONTEXT_NAME = "Server";

    private static final Logger LOG = LoggerFactory.getLogger(ZooKeeperSaslServer.class);
    private final Login login;
    private SaslServer saslServer;
    private CallbackHandler callbackHandler;

    ZooKeeperSaslServer(final Login login) {
        this.login = login;
    }

    /**
     * Picks the SASL mechanism from the first client packet: a DIGEST-MD5
     * client starts with an empty token, a SCRAM client with a GS2 header
     * ('n'/'y'/'p'), a GSSAPI client with an ASN.1 token (0x60). A server
     * without a Kerberos principal keeps the historical behavior and
     * negotiates DIGEST-MD5 or SCRAM. No wire protocol change is involved.
     */
    private SaslServer createSaslServer(byte[] firstToken) {
        synchronized (login) {
            Subject subject = login.getSubject();
            boolean hasKerberosPrincipal = subject != null && !subject.getPrincipals().isEmpty();
            callbackHandler = login.newCallbackHandler();
            if (isScramFirstToken(firstToken)) {
                if (subject == null) {
                    return null;
                }
                LOG.info("serving SCRAM-SHA-256 to a client that started with a GS2 header");
                return new ScramSaslServer(callbackHandler);
            }
            if (hasKerberosPrincipal && firstToken.length > 0) {
                return SecurityUtils.createGssSaslServer(subject, callbackHandler, LOG);
            }
            if (subject == null) {
                return null;
            }
            return SecurityUtils.createDigestSaslServer("zookeeper", "zk-sasl-md5", callbackHandler, LOG);
        }
    }

    /**
     * A SCRAM client-first message starts with the GS2 cbind flag; a GSSAPI
     * initial token always starts with the ASN.1 APPLICATION 0 tag (0x60), so
     * the two cannot collide.
     */
    private static boolean isScramFirstToken(byte[] firstToken) {
        return firstToken.length > 0
            && (firstToken[0] == 'n' || firstToken[0] == 'y' || firstToken[0] == 'p');
    }

    /**
     * Returns whether the completed authentication used a delegation token
     * rather than a Kerberos ticket or a static DIGEST user.
     */
    public boolean isTokenAuthenticated() {
        return callbackHandler instanceof SaslServerCallbackHandler
            && ((SaslServerCallbackHandler) callbackHandler).isTokenAuthenticated();
    }

    public byte[] evaluateResponse(byte[] response) throws SaslException {
        if (saslServer == null) {
            saslServer = createSaslServer(response);
            if (saslServer == null) {
                throw new SaslException("failed to create a SaslServer for the client response");
            }
        }
        return saslServer.evaluateResponse(response);
    }

    public boolean isComplete() {
        return saslServer != null && saslServer.isComplete();
    }

    public String getAuthorizationID() {
        return saslServer.getAuthorizationID();
    }

}




