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

package org.apache.zookeeper.server.token;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.zookeeper.ZooDefs.OpCode;
import org.apache.zookeeper.common.Time;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.proto.CancelDelegationTokenRequest;
import org.apache.zookeeper.server.DataNode;
import org.apache.zookeeper.server.Request;
import org.apache.zookeeper.server.RequestProcessor;
import org.apache.zookeeper.server.RequestRecord;
import org.apache.zookeeper.server.ZKDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Removes expired delegation tokens from the store. Modeled after
 * {@link org.apache.zookeeper.server.ContainerManager}: meant to run on the
 * leader (or a standalone server), periodically scans the token znodes and
 * posts internal cancel requests through the normal request pipeline, so the
 * deletions replicate as ordinary delete transactions.
 */
public class DelegationTokenCleanupManager {

    public static final String TOKEN_AUTH_CLEANUP_INTERVAL = "zookeeper.tokenAuth.cleanupIntervalMs";
    public static final long DEFAULT_CLEANUP_INTERVAL_MS = 60L * 60 * 1000;

    private static final Logger LOG = LoggerFactory.getLogger(DelegationTokenCleanupManager.class);

    // internal requests carry super auth so the cancel permission check passes
    private static final List<Id> SYSTEM_AUTH_INFO =
        Collections.singletonList(new Id("super", "delegation-token-cleanup"));

    private final ZKDatabase zkDb;
    private final RequestProcessor requestProcessor;
    private final long checkIntervalMs;
    private final Timer timer;
    private final AtomicReference<TimerTask> task = new AtomicReference<>(null);

    public DelegationTokenCleanupManager(ZKDatabase zkDb, RequestProcessor requestProcessor) {
        this(zkDb, requestProcessor, Long.getLong(TOKEN_AUTH_CLEANUP_INTERVAL, DEFAULT_CLEANUP_INTERVAL_MS));
    }

    public DelegationTokenCleanupManager(ZKDatabase zkDb, RequestProcessor requestProcessor, long checkIntervalMs) {
        this.zkDb = zkDb;
        this.requestProcessor = requestProcessor;
        this.checkIntervalMs = checkIntervalMs;
        timer = new Timer("DelegationTokenCleanupTask", true);
        LOG.info("Using checkIntervalMs={}", checkIntervalMs);
    }

    /**
     * Start or restart the periodic check. Safe to call multiple times.
     */
    public void start() {
        if (task.get() == null) {
            TimerTask timerTask = new TimerTask() {
                @Override
                public void run() {
                    try {
                        checkTokens();
                    } catch (Throwable e) {
                        LOG.error("Error checking delegation tokens", e);
                    }
                }
            };
            if (task.compareAndSet(null, timerTask)) {
                timer.scheduleAtFixedRate(timerTask, checkIntervalMs, checkIntervalMs);
            }
        }
    }

    /**
     * Stop the periodic check. Safe to call multiple times.
     */
    public void stop() {
        TimerTask timerTask = task.getAndSet(null);
        if (timerTask != null) {
            timerTask.cancel();
        }
        timer.cancel();
    }

    /**
     * Scans the token store once and posts cancel requests for expired tokens.
     * Public so tests can trigger a pass directly.
     */
    public void checkTokens() {
        DataNode parent = zkDb.getDataTree().getNode(DelegationTokenStore.TOKEN_NODE);
        if (parent == null) {
            return;
        }
        List<String> children;
        synchronized (parent) {
            children = new ArrayList<>(parent.getChildren());
        }
        long now = Time.currentWallTime();
        for (String child : children) {
            String path = DelegationTokenStore.TOKEN_NODE + "/" + child;
            DataNode node = zkDb.getDataTree().getNode(path);
            if (node == null) {
                continue;
            }
            byte[] identifier;
            long expiry;
            try {
                byte[] data = node.getData();
                expiry = DelegationTokenStore.entryExpiry(data);
                identifier = DelegationTokenStore.entryIdentifier(data);
            } catch (IOException e) {
                LOG.warn("Skipping malformed token store entry {}", path);
                continue;
            }
            if (now <= expiry) {
                continue;
            }
            CancelDelegationTokenRequest record = new CancelDelegationTokenRequest(identifier);
            Request request = new Request(
                null, 0, 0, OpCode.cancelDelegationToken, RequestRecord.fromRecord(record), SYSTEM_AUTH_INFO);
            try {
                LOG.info("Cancelling expired delegation token {}", path);
                postCancelRequest(request);
            } catch (Exception e) {
                LOG.error("Could not cancel expired delegation token {}", path, e);
            }
        }
    }

    // VisibleForTesting
    protected void postCancelRequest(Request request) throws RequestProcessor.RequestProcessorException {
        requestProcessor.processRequest(request);
    }

}
