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

package org.apache.zookeeper.delegation;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.security.auth.login.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.Watcher.Event.KeeperState;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.client.ZKClientConfig;
import org.apache.zookeeper.proto.GetDelegationTokenResponse;

/**
 * Client-side glue between ZooKeeper delegation tokens and the Hadoop
 * {@code Token}/{@code Credentials} machinery.
 */
public final class ZooKeeperDelegationTokens {

    public static final int DEFAULT_SESSION_TIMEOUT_MS = 30000;

    private static final int CONNECT_TIMEOUT_SECONDS = 30;
    private static final String DIGEST_LOGIN_MODULE = "org.apache.zookeeper.server.auth.DigestLoginModule";
    private static final String DEFAULT_CLIENT_SECTION = "Client";

    private ZooKeeperDelegationTokens() {
    }

    /** An issued token together with its current expiry time. */
    public static final class ObtainedToken {

        private final Token<ZooKeeperDelegationTokenIdentifier> token;
        private final long expiryTime;

        ObtainedToken(Token<ZooKeeperDelegationTokenIdentifier> token, long expiryTime) {
            this.token = token;
            this.expiryTime = expiryTime;
        }

        public Token<ZooKeeperDelegationTokenIdentifier> getToken() {
            return token;
        }

        public long getExpiryTime() {
            return expiryTime;
        }

    }

    /**
     * Requests a delegation token from the ensemble. The connection uses the
     * ambient ZooKeeper client SASL configuration (JAAS), so the caller must
     * already be able to authenticate with a non-token mechanism.
     *
     * @param connectString ensemble connect string
     * @param renewer principal allowed to renew, may be empty
     * @param maxLifetimeMs requested lifetime, 0 for the server default
     * @param service Hadoop token service the token is filed under
     */
    public static ObtainedToken obtainToken(String connectString, String renewer, long maxLifetimeMs, String service)
        throws IOException, InterruptedException {
        ZooKeeper zk = connect(connectString, DEFAULT_SESSION_TIMEOUT_MS);
        try {
            GetDelegationTokenResponse response = zk.getDelegationToken(renewer, maxLifetimeMs);
            Token<ZooKeeperDelegationTokenIdentifier> token = new Token<>(
                response.getIdentifier(),
                response.getPassword(),
                ZooKeeperDelegationTokenIdentifier.KIND_NAME,
                new Text(service));
            return new ObtainedToken(token, response.getExpiryTime());
        } catch (KeeperException e) {
            throw new IOException("failed to obtain a ZooKeeper delegation token from " + connectString, e);
        } finally {
            closeQuietly(zk);
        }
    }

    /**
     * Picks the ZooKeeper delegation token filed under the given service, or
     * null when the credentials hold none.
     */
    public static Token<?> selectToken(Credentials credentials, String service) {
        Token<?> token = credentials.getToken(new Text(service));
        if (token != null && ZooKeeperDelegationTokenIdentifier.KIND_NAME.equals(token.getKind())) {
            return token;
        }
        return null;
    }

    /**
     * Picks the ZooKeeper delegation token filed under the given service from
     * the current UGI credentials. In a YARN container or Spark executor the
     * distributed job credentials (including HADOOP_TOKEN_FILE_LOCATION) are
     * already loaded there, so this is the consumer-side lookup.
     */
    public static Token<?> selectTokenFromUgi(String service) throws IOException {
        return selectToken(UserGroupInformation.getCurrentUser().getCredentials(), service);
    }

    /**
     * Convenience for token consumers: picks the token for the service from
     * the current UGI and installs the JAAS glue so a plain ZooKeeper client
     * authenticates with it. Returns false when the UGI holds no such token.
     */
    public static boolean installTokenFromUgi(String service) throws IOException {
        Token<?> token = selectTokenFromUgi(service);
        if (token == null) {
            return false;
        }
        installTokenJaasConfiguration(token);
        return true;
    }

    /**
     * Installs a JAAS configuration whose ZooKeeper client section carries the
     * token credentials, so a plain ZooKeeper client in this JVM authenticates
     * with the token. Every other JAAS section keeps delegating to the
     * previously installed configuration. Returns the previous configuration
     * so the caller can restore it.
     */
    public static Configuration installTokenJaasConfiguration(Token<?> token) {
        Configuration base = currentJaasConfigurationOrNull();
        Configuration.setConfiguration(
            new DelegationTokenJaasConfiguration(base, clientSectionName(), DIGEST_LOGIN_MODULE, token));
        return base;
    }

    static String clientSectionName() {
        return System.getProperty(ZKClientConfig.LOGIN_CONTEXT_NAME_KEY, DEFAULT_CLIENT_SECTION);
    }

    private static Configuration currentJaasConfigurationOrNull() {
        try {
            return Configuration.getConfiguration();
        } catch (SecurityException e) {
            return null;
        }
    }

    /**
     * Opens a ZooKeeper session and waits for it to connect.
     */
    public static ZooKeeper connect(String connectString, int sessionTimeoutMs)
        throws IOException, InterruptedException {
        CountDownLatch connected = new CountDownLatch(1);
        ZooKeeper zk = new ZooKeeper(connectString, sessionTimeoutMs, event -> {
            if (event.getState() == KeeperState.SyncConnected) {
                connected.countDown();
            }
        });
        boolean ok = false;
        try {
            if (!connected.await(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IOException("timed out connecting to " + connectString);
            }
            ok = true;
            return zk;
        } finally {
            if (!ok) {
                closeQuietly(zk);
            }
        }
    }

    static void closeQuietly(ZooKeeper zk) {
        try {
            zk.close();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

}
