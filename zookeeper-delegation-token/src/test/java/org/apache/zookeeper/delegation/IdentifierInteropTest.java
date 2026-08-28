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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import org.apache.hadoop.io.Text;
import org.apache.zookeeper.server.token.DelegationTokenIdentifier;
import org.junit.jupiter.api.Test;

/**
 * Byte-level interop between the ZooKeeper-core identifier encoding and the
 * real Hadoop AbstractDelegationTokenIdentifier Writable implementation.
 */
public class IdentifierInteropTest {

    @Test
    public void testCoreEncodingReadableByHadoop() throws IOException {
        DelegationTokenIdentifier core = new DelegationTokenIdentifier(
            "сервис/host@REALM.RU", "rm/rm.example.com@REALM.RU", "proxyUser",
            1700000000123L, 1700604800456L, 123456, 7);

        ZooKeeperDelegationTokenIdentifier hadoop = new ZooKeeperDelegationTokenIdentifier();
        hadoop.readFields(new DataInputStream(new ByteArrayInputStream(core.toBytes())));

        assertEquals(core.getOwner(), hadoop.getOwner().toString());
        assertEquals(core.getRenewer(), hadoop.getRenewer().toString());
        assertEquals(core.getRealUser(), hadoop.getRealUser().toString());
        assertEquals(core.getIssueDate(), hadoop.getIssueDate());
        assertEquals(core.getMaxDate(), hadoop.getMaxDate());
        assertEquals(core.getSequenceNumber(), hadoop.getSequenceNumber());
        assertEquals(core.getMasterKeyId(), hadoop.getMasterKeyId());
    }

    @Test
    public void testHadoopEncodingReadableByCore() throws IOException {
        ZooKeeperDelegationTokenIdentifier hadoop = new ZooKeeperDelegationTokenIdentifier(
            new Text("alice@EXAMPLE.COM"), new Text("bob"), new Text(""));
        hadoop.setIssueDate(1756339200000L);
        hadoop.setMaxDate(1756944000000L);
        hadoop.setSequenceNumber(42);
        hadoop.setMasterKeyId(1);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        hadoop.write(new DataOutputStream(buffer));
        DelegationTokenIdentifier core = DelegationTokenIdentifier.fromBytes(buffer.toByteArray());

        assertEquals("alice@EXAMPLE.COM", core.getOwner());
        assertEquals("bob", core.getRenewer());
        assertEquals("", core.getRealUser());
        assertEquals(1756339200000L, core.getIssueDate());
        assertEquals(1756944000000L, core.getMaxDate());
        assertEquals(42, core.getSequenceNumber());
        assertEquals(1, core.getMasterKeyId());

        // and the round trip back to Writable form is identical
        assertArrayEquals(buffer.toByteArray(), core.toBytes());
    }

}
