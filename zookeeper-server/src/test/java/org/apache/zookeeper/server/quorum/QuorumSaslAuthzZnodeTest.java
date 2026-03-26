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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.sasl.SaslException;
import org.apache.jute.BinaryOutputArchive;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.server.Request;
import org.apache.zookeeper.server.ZKDatabase;
import org.apache.zookeeper.server.persistence.FileTxnSnapLog;
import org.apache.zookeeper.server.quorum.flexible.QuorumVerifier;
import org.apache.zookeeper.txn.CreateTxn;
import org.apache.zookeeper.txn.DeleteTxn;
import org.apache.zookeeper.txn.MultiTxn;
import org.apache.zookeeper.txn.SetDataTxn;
import org.apache.zookeeper.txn.Txn;
import org.apache.zookeeper.txn.TxnHeader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class QuorumSaslAuthzZnodeTest {

    @TempDir
    public File tmpDir;

    @Test
    public void testAuthzHostsRefreshFromZnode() throws Exception {
        TrackingQuorumPeer peer = createPeer();
        LeaderZooKeeperServer zks = createServer(peer);
        String path = peer.getQuorumSaslAuthzZnodePath();

        // Create the authz znode
        TxnHeader createHdr = new TxnHeader(1, 1, 1, 1, ZooDefs.OpCode.create);
        CreateTxn createTxn = new CreateTxn(path, "HostA,hostB".getBytes(StandardCharsets.UTF_8),
            ZooDefs.Ids.OPEN_ACL_UNSAFE, false, 0);
        Request createReq = new Request(null, 1, 1, ZooDefs.OpCode.create, null, null);
        createReq.setHdr(createHdr);
        createReq.setTxn(createTxn);
        zks.processTxn(createReq);

        assertEquals(new HashSet<>(Arrays.asList("hosta", "hostb")), peer.getManualSaslAuthzHosts());
        assertEquals(1, peer.getRefreshCalls());

        // Update the authz znode
        TxnHeader setHdr = new TxnHeader(1, 1, 2, 2, ZooDefs.OpCode.setData);
        SetDataTxn setDataTxn = new SetDataTxn(path, "hostC".getBytes(StandardCharsets.UTF_8), -1);
        Request setReq = new Request(null, 1, 2, ZooDefs.OpCode.setData, null, null);
        setReq.setHdr(setHdr);
        setReq.setTxn(setDataTxn);
        zks.processTxn(setReq);

        assertEquals(new HashSet<>(Arrays.asList("hostc")), peer.getManualSaslAuthzHosts());
        assertEquals(2, peer.getRefreshCalls());

        // Delete the authz znode
        TxnHeader deleteHdr = new TxnHeader(1, 1, 3, 3, ZooDefs.OpCode.delete);
        DeleteTxn deleteTxn = new DeleteTxn(path);
        Request deleteReq = new Request(null, 1, 3, ZooDefs.OpCode.delete, null, null);
        deleteReq.setHdr(deleteHdr);
        deleteReq.setTxn(deleteTxn);
        zks.processTxn(deleteReq);

        assertTrue(peer.getManualSaslAuthzHosts().isEmpty());
        assertEquals(3, peer.getRefreshCalls());
    }

    @Test
    public void testAuthzHostsRefreshFromMultiTxn() throws Exception {
        TrackingQuorumPeer peer = createPeer();
        LeaderZooKeeperServer zks = createServer(peer);
        String path = peer.getQuorumSaslAuthzZnodePath();

        // Multi txn: create parent + create authz znode
        CreateTxn parentTxn = new CreateTxn("/zookeeper", new byte[0],
            ZooDefs.Ids.OPEN_ACL_UNSAFE, false, 0);
        CreateTxn authzTxn = new CreateTxn(path, "hostX,hostY".getBytes(StandardCharsets.UTF_8),
            ZooDefs.Ids.OPEN_ACL_UNSAFE, false, 0);

        List<Txn> txns = new ArrayList<>();
        txns.add(new Txn(ZooDefs.OpCode.create, serializeTxn(parentTxn)));
        txns.add(new Txn(ZooDefs.OpCode.create, serializeTxn(authzTxn)));

        TxnHeader multiHdr = new TxnHeader(1, 1, 1, 1, ZooDefs.OpCode.multi);
        MultiTxn multiTxn = new MultiTxn(txns);
        Request multiReq = new Request(null, 1, 1, ZooDefs.OpCode.multi, null, null);
        multiReq.setHdr(multiHdr);
        multiReq.setTxn(multiTxn);
        zks.processTxn(multiReq);

        assertEquals(new HashSet<>(Arrays.asList("hostx", "hosty")), peer.getManualSaslAuthzHosts());
        assertEquals(1, peer.getRefreshCalls());
    }

    @Test
    public void testUnrelatedZnodeDoesNotTriggerRefresh() throws Exception {
        TrackingQuorumPeer peer = createPeer();
        LeaderZooKeeperServer zks = createServer(peer);

        // Create an unrelated znode
        TxnHeader createHdr = new TxnHeader(1, 1, 1, 1, ZooDefs.OpCode.create);
        CreateTxn createTxn = new CreateTxn("/some/other/path", "data".getBytes(StandardCharsets.UTF_8),
            ZooDefs.Ids.OPEN_ACL_UNSAFE, false, 0);
        Request createReq = new Request(null, 1, 1, ZooDefs.OpCode.create, null, null);
        createReq.setHdr(createHdr);
        createReq.setTxn(createTxn);
        zks.processTxn(createReq);

        assertTrue(peer.getManualSaslAuthzHosts().isEmpty());
        assertEquals(0, peer.getRefreshCalls());
    }

    private TrackingQuorumPeer createPeer() throws SaslException {
        TrackingQuorumPeer peer = new TrackingQuorumPeer();
        peer.setTickTime(2000);
        peer.setMinSessionTimeout(4000);
        peer.setMaxSessionTimeout(40000);
        peer.setInitialConfig("server.1=localhost:2888:3888:participant");
        peer.setQuorumSaslEnabled(true);
        peer.setQuorumSaslAuthzZnodeEnabled(true);
        peer.setQuorumSaslAuthzZnodePath("/zookeeper/quorumAuthzHosts");
        return peer;
    }

    private LeaderZooKeeperServer createServer(TrackingQuorumPeer peer) throws Exception {
        FileTxnSnapLog snapLog = new FileTxnSnapLog(tmpDir, tmpDir);
        ZKDatabase zkDb = new ZKDatabase(snapLog);
        return new LeaderZooKeeperServer(snapLog, peer, zkDb);
    }

    @Test
    public void testDisabledFeatureDoesNotTriggerRefresh() throws Exception {
        TrackingQuorumPeer peer = new TrackingQuorumPeer();
        peer.setTickTime(2000);
        peer.setMinSessionTimeout(4000);
        peer.setMaxSessionTimeout(40000);
        peer.setInitialConfig("server.1=localhost:2888:3888:participant");
        peer.setQuorumSaslEnabled(true);
        peer.setQuorumSaslAuthzZnodeEnabled(false);
        peer.setQuorumSaslAuthzZnodePath("/zookeeper/quorumAuthzHosts");

        LeaderZooKeeperServer zks = createServer(peer);
        String path = peer.getQuorumSaslAuthzZnodePath();

        TxnHeader createHdr = new TxnHeader(1, 1, 1, 1, ZooDefs.OpCode.create);
        CreateTxn createTxn = new CreateTxn(path, "hostA".getBytes(StandardCharsets.UTF_8),
            ZooDefs.Ids.OPEN_ACL_UNSAFE, false, 0);
        Request createReq = new Request(null, 1, 1, ZooDefs.OpCode.create, null, null);
        createReq.setHdr(createHdr);
        createReq.setTxn(createTxn);
        zks.processTxn(createReq);

        assertTrue(peer.getManualSaslAuthzHosts().isEmpty());
        assertEquals(0, peer.getRefreshCalls());
    }

    @Test
    public void testParseAuthzHostsEdgeCases() throws Exception {
        TrackingQuorumPeer peer = createPeer();

        peer.setManualSaslAuthzHosts("hostA, hostB\thostC,,  hostD");
        assertEquals(
            new HashSet<>(Arrays.asList("hosta", "hostb", "hostc", "hostd")),
            peer.getManualSaslAuthzHosts());

        peer.setManualSaslAuthzHosts("   ");
        assertTrue(peer.getManualSaslAuthzHosts().isEmpty());

        peer.setManualSaslAuthzHosts(null);
        assertTrue(peer.getManualSaslAuthzHosts().isEmpty());

        peer.setManualSaslAuthzHosts("SingleHost");
        assertEquals(
            new HashSet<>(Arrays.asList("singlehost")),
            peer.getManualSaslAuthzHosts());
    }

    private static byte[] serializeTxn(org.apache.jute.Record record) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            BinaryOutputArchive boa = BinaryOutputArchive.getArchive(baos);
            record.serialize(boa, "request");
            return baos.toByteArray();
        }
    }

    private static class TrackingQuorumPeer extends QuorumPeer {
        private final AtomicInteger refreshCalls = new AtomicInteger(0);

        TrackingQuorumPeer() throws SaslException {
            super();
        }

        @Override
        public void refreshQuorumSaslAuthzHosts(QuorumVerifier... extraQVs) {
            refreshCalls.incrementAndGet();
        }

        int getRefreshCalls() {
            return refreshCalls.get();
        }

        @Override
        Set<String> getManualSaslAuthzHosts() {
            return super.getManualSaslAuthzHosts();
        }
    }

}
