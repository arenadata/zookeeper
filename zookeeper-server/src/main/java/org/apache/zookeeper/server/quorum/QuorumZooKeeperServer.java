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

package org.apache.zookeeper.server.quorum;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import org.apache.jute.Record;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.MultiOperationRecord;
import org.apache.zookeeper.Op;
import org.apache.zookeeper.ZooDefs.OpCode;
import org.apache.zookeeper.data.Stat;
import org.apache.zookeeper.metrics.MetricsContext;
import org.apache.zookeeper.proto.CreateRequest;
import org.apache.zookeeper.server.ByteBufferInputStream;
import org.apache.zookeeper.server.DataTree.ProcessTxnResult;
import org.apache.zookeeper.server.Request;
import org.apache.zookeeper.server.ServerMetrics;
import org.apache.zookeeper.server.ZKDatabase;
import org.apache.zookeeper.server.ZooKeeperServer;
import org.apache.zookeeper.server.persistence.FileTxnSnapLog;
import org.apache.zookeeper.txn.TxnHeader;

/**
 * Abstract base class for all ZooKeeperServers that participate in
 * a quorum.
 */
public abstract class QuorumZooKeeperServer extends ZooKeeperServer {

    public final QuorumPeer self;
    protected UpgradeableSessionTracker upgradeableSessionTracker;

    protected QuorumZooKeeperServer(FileTxnSnapLog logFactory, int tickTime, int minSessionTimeout,
                                    int maxSessionTimeout, int listenBacklog, ZKDatabase zkDb, QuorumPeer self) {
        super(logFactory, tickTime, minSessionTimeout, maxSessionTimeout, listenBacklog, zkDb, self.getInitialConfig(),
              self.isReconfigEnabled());
        this.self = self;
    }

    @Override
    public synchronized void startup() {
        super.startup();
        refreshAuthzHostsFromZnode();
    }

    @Override
    public synchronized void startupWithoutServing() {
        super.startupWithoutServing();
        refreshAuthzHostsFromZnode();
    }

    @Override
    protected void startSessionTracker() {
        upgradeableSessionTracker = (UpgradeableSessionTracker) sessionTracker;
        upgradeableSessionTracker.start();
    }

    public Request checkUpgradeSession(Request request) throws IOException, KeeperException {
        if (request.isThrottled()) {
            return null;
        }

        // If this is a request for a local session and it is to
        // create an ephemeral node, then upgrade the session and return
        // a new session request for the leader.
        // This is called by the request processor thread (either follower
        // or observer request processor), which is unique to a learner.
        // So will not be called concurrently by two threads.
        if ((request.type != OpCode.create && request.type != OpCode.create2 && request.type != OpCode.multi)
            || !upgradeableSessionTracker.isLocalSession(request.sessionId)) {
            return null;
        }

        if (OpCode.multi == request.type) {
            MultiOperationRecord multiTransactionRecord = new MultiOperationRecord();
            request.request.rewind();
            ByteBufferInputStream.byteBuffer2Record(request.request, multiTransactionRecord);
            request.request.rewind();
            boolean containsEphemeralCreate = false;
            for (Op op : multiTransactionRecord) {
                if (op.getType() == OpCode.create || op.getType() == OpCode.create2) {
                    CreateRequest createRequest = (CreateRequest) op.toRequestRecord();
                    CreateMode createMode = CreateMode.fromFlag(createRequest.getFlags());
                    if (createMode.isEphemeral()) {
                        containsEphemeralCreate = true;
                        break;
                    }
                }
            }
            if (!containsEphemeralCreate) {
                return null;
            }
        } else {
            CreateRequest createRequest = new CreateRequest();
            request.request.rewind();
            ByteBufferInputStream.byteBuffer2Record(request.request, createRequest);
            request.request.rewind();
            CreateMode createMode = CreateMode.fromFlag(createRequest.getFlags());
            if (!createMode.isEphemeral()) {
                return null;
            }
        }

        // Uh oh.  We need to upgrade before we can proceed.
        if (!self.isLocalSessionsUpgradingEnabled()) {
            throw new KeeperException.EphemeralOnLocalSessionException();
        }

        return makeUpgradeRequest(request.sessionId);
    }

    private Request makeUpgradeRequest(long sessionId) {
        // Make sure to atomically check local session status, upgrade
        // session, and make the session creation request.  This is to
        // avoid another thread upgrading the session in parallel.
        synchronized (upgradeableSessionTracker) {
            if (upgradeableSessionTracker.isLocalSession(sessionId)) {
                int timeout = upgradeableSessionTracker.upgradeSession(sessionId);
                ByteBuffer to = ByteBuffer.allocate(4);
                to.putInt(timeout);
                return new Request(null, sessionId, 0, OpCode.createSession, to, null);
            }
        }
        return null;
    }

    /**
     * Implements the SessionUpgrader interface,
     *
     * @param sessionId
     */
    public void upgrade(long sessionId) {
        Request request = makeUpgradeRequest(sessionId);
        if (request != null) {
            LOG.info("Upgrading session 0x{}", Long.toHexString(sessionId));
            // This must be a global request
            submitRequest(request);
        }
    }

    @Override
    protected void setLocalSessionFlag(Request si) {
        // We need to set isLocalSession to tree for these type of request
        // so that the request processor can process them correctly.
        switch (si.type) {
        case OpCode.createSession:
            if (self.areLocalSessionsEnabled()) {
                // All new sessions local by default.
                si.setLocalSession(true);
            }
            break;
        case OpCode.closeSession:
            String reqType = "global";
            if (upgradeableSessionTracker.isLocalSession(si.sessionId)) {
                si.setLocalSession(true);
                reqType = "local";
            }
            LOG.info("Submitting {} closeSession request for session 0x{}", reqType, Long.toHexString(si.sessionId));
            break;
        default:
            break;
        }
    }

    @Override
    public void dumpConf(PrintWriter pwriter) {
        super.dumpConf(pwriter);

        pwriter.print("initLimit=");
        pwriter.println(self.getInitLimit());
        pwriter.print("syncLimit=");
        pwriter.println(self.getSyncLimit());
        pwriter.print("electionAlg=");
        pwriter.println(self.getElectionType());
        pwriter.print("electionPort=");
        pwriter.println(self.getElectionAddress().getAllPorts()
                .stream().map(Objects::toString).collect(Collectors.joining("|")));
        pwriter.print("quorumPort=");
        pwriter.println(self.getQuorumAddress().getAllPorts()
                        .stream().map(Objects::toString).collect(Collectors.joining("|")));
        pwriter.print("peerType=");
        pwriter.println(self.getLearnerType().ordinal());
        pwriter.println("membership: ");
        pwriter.print(self.getQuorumVerifier().toString());
    }

    @Override
    protected void setState(State state) {
        this.state = state;
    }

    @Override
    protected void registerMetrics() {
        super.registerMetrics();

        MetricsContext rootContext = ServerMetrics.getMetrics().getMetricsProvider().getRootContext();

        rootContext.registerGauge("quorum_size", () -> {
            return self.getQuorumSize();
        });
    }

    @Override
    protected void unregisterMetrics() {
        super.unregisterMetrics();

        MetricsContext rootContext = ServerMetrics.getMetrics().getMetricsProvider().getRootContext();

        rootContext.unregisterGauge("quorum_size");
    }

    @Override
    public void dumpMonitorValues(BiConsumer<String, Object> response) {
        super.dumpMonitorValues(response);
        response.accept("peer_state", self.getDetailedPeerState());
    }

    @Override
    public ProcessTxnResult processTxn(TxnHeader hdr, Record txn) {
        ProcessTxnResult rc = super.processTxn(hdr, txn);
        maybeRefreshAuthzHostsFromTxn(rc);
        return rc;
    }

    @Override
    public ProcessTxnResult processTxn(Request request) {
        ProcessTxnResult rc = super.processTxn(request);
        maybeRefreshAuthzHostsFromTxn(rc);
        return rc;
    }

    private void maybeRefreshAuthzHostsFromTxn(ProcessTxnResult rc) {
        if (rc == null) {
            return;
        }
        if (!self.isQuorumSaslAuthEnabled()) {
            return;
        }
        String znodePath = self.getQuorumSaslAuthzZnodePath();
        if (znodePath == null || znodePath.isEmpty()) {
            return;
        }

        if (rc.multiResult != null) {
            for (ProcessTxnResult sub : rc.multiResult) {
                if (isAuthzZnodeTxn(sub, znodePath)) {
                    if (sub.type == OpCode.delete) {
                        clearAuthzHostsFromZnode();
                    } else {
                        refreshAuthzHostsFromZnode();
                    }
                    return;
                }
            }
            return;
        }

        if (rc.path != null && rc.path.contains("quorumAuthzHosts")) {
            LOG.info("Authz znode candidate txn: type={}, path={}, expected={}", rc.type, rc.path, znodePath);
        }
        if (isAuthzZnodeTxn(rc, znodePath)) {
            LOG.info("Authz znode txn applied: type={}, path={}", rc.type, rc.path);
            if (rc.type == OpCode.delete) {
                clearAuthzHostsFromZnode();
            } else {
                refreshAuthzHostsFromZnode();
            }
        }
    }

    private static boolean isAuthzZnodeTxn(ProcessTxnResult rc, String znodePath) {
        if (rc == null || rc.path == null) {
            return false;
        }
        if (!znodePath.equals(rc.path)) {
            return false;
        }
        return rc.type == OpCode.create
               || rc.type == OpCode.create2
               || rc.type == OpCode.createContainer
               || rc.type == OpCode.setData
               || rc.type == OpCode.delete;
    }

    private void refreshAuthzHostsFromZnode() {
        if (!self.isQuorumSaslAuthEnabled()) {
            return;
        }
        String path = self.getQuorumSaslAuthzZnodePath();
        if (path == null || path.isEmpty()) {
            return;
        }
        try {
            byte[] data = getZKDatabase().getDataTree().getData(path, new Stat(), null);
            if (data == null) {
                LOG.info("Authz znode read returned null data for {}", path);
                return;
            }
            if (data.length == 0) {
                LOG.info("Authz znode read returned empty data for {}", path);
                self.clearManualSaslAuthzHosts();
            } else {
                LOG.info("Authz znode read {} bytes for {}", data.length, path);
                self.setManualSaslAuthzHosts(new String(data, StandardCharsets.UTF_8));
            }
        } catch (KeeperException.NoNodeException e) {
            LOG.info("Authz znode missing at {}", path);
            return;
        } catch (Exception e) {
            LOG.warn("Failed to refresh quorum SASL authz hosts from znode {}", path, e);
            return;
        }

        self.refreshQuorumSaslAuthzHosts();
    }

    private void clearAuthzHostsFromZnode() {
        if (!self.isQuorumSaslAuthEnabled()) {
            return;
        }
        self.clearManualSaslAuthzHosts();
        self.refreshQuorumSaslAuthzHosts();
    }

}
