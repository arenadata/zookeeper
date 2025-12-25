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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.security.sasl.SaslException;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.server.quorum.flexible.QuorumVerifier;
import org.apache.zookeeper.txn.CreateTxn;
import org.apache.zookeeper.txn.DeleteTxn;
import org.apache.zookeeper.txn.SetDataTxn;
import org.apache.zookeeper.txn.TxnHeader;
import org.apache.zookeeper.server.ZKDatabase;
import org.apache.zookeeper.server.persistence.FileTxnSnapLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class QuorumSaslAuthzZnodeTest {

    @TempDir
    public File tmpDir;

    @Test
    public void testAuthzHostsRefreshFromZnode() throws Exception {
        TrackingQuorumPeer peer = new TrackingQuorumPeer();
        peer.setTickTime(2000);
        peer.setMinSessionTimeout(4000);
        peer.setMaxSessionTimeout(40000);
        peer.setInitialConfig("server.1=localhost:2888:3888:participant");
        peer.setQuorumSaslEnabled(true);
        peer.setQuorumSaslAuthzZnodeEnabled(true);
        peer.setQuorumSaslAuthzZnodePath("/zookeeper/quorumAuthzHosts");

        FileTxnSnapLog snapLog = new FileTxnSnapLog(tmpDir, tmpDir);
        ZKDatabase zkDb = new ZKDatabase(snapLog);
        LeaderZooKeeperServer zks = new LeaderZooKeeperServer(snapLog, peer, zkDb);

        String path = peer.getQuorumSaslAuthzZnodePath();

        TxnHeader createHdr = new TxnHeader(1, 1, 1, 1, ZooDefs.OpCode.create);
        CreateTxn createTxn = new CreateTxn(path, "HostA,hostB".getBytes(StandardCharsets.UTF_8),
            ZooDefs.Ids.OPEN_ACL_UNSAFE, false, 0);
        zks.processTxn(createHdr, createTxn);

        assertEquals(new HashSet<String>(Arrays.asList("hosta", "hostb")), peer.getManualSaslAuthzHosts());
        assertEquals(1, peer.getRefreshCalls());

        TxnHeader setHdr = new TxnHeader(1, 1, 2, 2, ZooDefs.OpCode.setData);
        SetDataTxn setDataTxn = new SetDataTxn(path, "hostC".getBytes(StandardCharsets.UTF_8), -1);
        zks.processTxn(setHdr, setDataTxn);

        assertEquals(new HashSet<String>(Arrays.asList("hostc")), peer.getManualSaslAuthzHosts());
        assertEquals(2, peer.getRefreshCalls());

        TxnHeader deleteHdr = new TxnHeader(1, 1, 3, 3, ZooDefs.OpCode.delete);
        DeleteTxn deleteTxn = new DeleteTxn(path);
        zks.processTxn(deleteHdr, deleteTxn);

        assertTrue(peer.getManualSaslAuthzHosts().isEmpty());
        assertEquals(3, peer.getRefreshCalls());
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
