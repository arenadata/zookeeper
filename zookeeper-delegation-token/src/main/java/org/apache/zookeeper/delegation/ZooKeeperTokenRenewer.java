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
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenRenewer;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooKeeper;

/**
 * Hadoop renewer for the ZOOKEEPER_DELEGATION_TOKEN kind, discovered via
 * ServiceLoader — put this jar on the YARN ResourceManager classpath so the
 * RM can renew and cancel ZooKeeper tokens of submitted applications.
 *
 * <p>The connect string is resolved from
 * {@code zookeeper.delegation.token.quorum.<service>} in the configuration,
 * falling back to interpreting the token service itself as a connect string.
 * The renew/cancel calls authenticate with the ambient ZooKeeper client SASL
 * configuration (JAAS) of the JVM, which must map to the token's renewer
 * principal.
 */
public class ZooKeeperTokenRenewer extends TokenRenewer {

    public static final String QUORUM_CONF_PREFIX = "zookeeper.delegation.token.quorum.";

    @Override
    public boolean handleKind(Text kind) {
        return ZooKeeperDelegationTokenIdentifier.KIND_NAME.equals(kind);
    }

    @Override
    public boolean isManaged(Token<?> token) {
        return true;
    }

    @Override
    public long renew(Token<?> token, Configuration conf) throws IOException, InterruptedException {
        ZooKeeper zk = connectFor(token, conf);
        try {
            return zk.renewDelegationToken(token.getIdentifier());
        } catch (KeeperException e) {
            throw new IOException("failed to renew ZooKeeper delegation token", e);
        } finally {
            ZooKeeperDelegationTokens.closeQuietly(zk);
        }
    }

    @Override
    public void cancel(Token<?> token, Configuration conf) throws IOException, InterruptedException {
        ZooKeeper zk = connectFor(token, conf);
        try {
            zk.cancelDelegationToken(token.getIdentifier());
        } catch (KeeperException e) {
            throw new IOException("failed to cancel ZooKeeper delegation token", e);
        } finally {
            ZooKeeperDelegationTokens.closeQuietly(zk);
        }
    }

    private static ZooKeeper connectFor(Token<?> token, Configuration conf) throws IOException, InterruptedException {
        String service = token.getService().toString();
        String quorum = conf.get(QUORUM_CONF_PREFIX + service, service);
        return ZooKeeperDelegationTokens.connect(quorum, ZooKeeperDelegationTokens.DEFAULT_SESSION_TIMEOUT_MS);
    }

}
