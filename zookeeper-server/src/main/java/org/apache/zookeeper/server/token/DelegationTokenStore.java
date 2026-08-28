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
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import org.apache.zookeeper.data.Id;

/**
 * Layout of the delegation token store kept in the ZooKeeper data tree.
 *
 * <p>Each active token lives at {@code /zookeeper/token/DT_&lt;sequenceNumber&gt;}
 * whose data is a store entry: a version byte, the current expiry time and the
 * serialized identifier. The nodes are written only by the server itself
 * (token opcodes and expiry cleanup), replicated as ordinary create/setData/delete
 * transactions and persisted in snapshots like any other znode.
 */
public final class DelegationTokenStore {

    public static final String TOKEN_NODE = "/zookeeper/token";
    public static final String TOKEN_NODE_PREFIX = TOKEN_NODE + "/DT_";

    /** AuthInfo scheme marking a session as token-authenticated. */
    public static final String TOKEN_AUTH_SCHEME = "token";

    private static final byte ENTRY_VERSION = 1;
    private static final int ENTRY_HEADER_LENGTH = 1 + 8;

    /**
     * Read access to stored token entries, keyed by the identifier sequence
     * number; returns null when the token is not in the store.
     */
    public interface EntryReader {

        byte[] entry(int sequenceNumber);

    }

    private DelegationTokenStore() {
    }

    public static String pathOf(int sequenceNumber) {
        return TOKEN_NODE_PREFIX + sequenceNumber;
    }

    public static byte[] encodeEntry(long expiryTime, byte[] identifierBytes) {
        ByteBuffer buffer = ByteBuffer.allocate(ENTRY_HEADER_LENGTH + identifierBytes.length);
        buffer.put(ENTRY_VERSION).putLong(expiryTime).put(identifierBytes);
        return buffer.array();
    }

    public static long entryExpiry(byte[] entry) throws IOException {
        checkEntry(entry);
        return ByteBuffer.wrap(entry, 1, 8).getLong();
    }

    public static byte[] entryIdentifier(byte[] entry) throws IOException {
        checkEntry(entry);
        return Arrays.copyOfRange(entry, ENTRY_HEADER_LENGTH, entry.length);
    }

    private static void checkEntry(byte[] entry) throws IOException {
        if (entry == null || entry.length <= ENTRY_HEADER_LENGTH || entry[0] != ENTRY_VERSION) {
            throw new IOException("malformed delegation token store entry");
        }
    }

    /**
     * Returns the SASL principal from the request auth info, or null when the
     * session is not SASL-authenticated.
     */
    public static String saslPrincipal(List<Id> authInfo) {
        if (authInfo == null) {
            return null;
        }
        for (Id id : authInfo) {
            if ("sasl".equals(id.getScheme())) {
                return id.getId();
            }
        }
        return null;
    }

    public static boolean isSuper(List<Id> authInfo) {
        if (authInfo == null) {
            return false;
        }
        for (Id id : authInfo) {
            if ("super".equals(id.getScheme())) {
                return true;
            }
        }
        return false;
    }

    public static boolean isTokenAuthenticated(List<Id> authInfo) {
        if (authInfo == null) {
            return false;
        }
        for (Id id : authInfo) {
            if (TOKEN_AUTH_SCHEME.equals(id.getScheme())) {
                return true;
            }
        }
        return false;
    }

}
