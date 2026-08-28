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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class DelegationTokenIdentifierTest {

    // Golden vectors generated with Hadoop 3.4.3 WritableUtils and Text to pin
    // byte compatibility with AbstractDelegationTokenIdentifier encoding.

    private static final Map<Long, String> VLONG_VECTORS = new LinkedHashMap<>();
    private static final Map<Integer, String> VINT_VECTORS = new LinkedHashMap<>();
    private static final Map<String, String> TEXT_VECTORS = new LinkedHashMap<>();

    static {
        VLONG_VECTORS.put(0L, "00");
        VLONG_VECTORS.put(1L, "01");
        VLONG_VECTORS.put(-1L, "ff");
        VLONG_VECTORS.put(127L, "7f");
        VLONG_VECTORS.put(128L, "8f80");
        VLONG_VECTORS.put(-112L, "90");
        VLONG_VECTORS.put(-113L, "8770");
        VLONG_VECTORS.put(255L, "8fff");
        VLONG_VECTORS.put(256L, "8e0100");
        VLONG_VECTORS.put(65535L, "8effff");
        VLONG_VECTORS.put(1234567890L, "8c499602d2");
        VLONG_VECTORS.put(-1234567890L, "84499602d1");
        VLONG_VECTORS.put(1756339200000L, "8a0198edf96000");
        VLONG_VECTORS.put(Long.MAX_VALUE, "887fffffffffffffff");
        VLONG_VECTORS.put(Long.MIN_VALUE, "807fffffffffffffff");

        VINT_VECTORS.put(0, "00");
        VINT_VECTORS.put(42, "2a");
        VINT_VECTORS.put(127, "7f");
        VINT_VECTORS.put(128, "8f80");
        VINT_VECTORS.put(1234567, "8d12d687");
        VINT_VECTORS.put(Integer.MAX_VALUE, "8c7fffffff");
        VINT_VECTORS.put(-1, "ff");

        TEXT_VECTORS.put("", "00");
        TEXT_VECTORS.put("alice", "05616c696365");
        TEXT_VECTORS.put("alice@EXAMPLE.COM", "11616c696365404558414d504c452e434f4d");
        TEXT_VECTORS.put("клиент", "0cd0bad0bbd0b8d0b5d0bdd182");
    }

    private static final String IDENT1_HEX =
        "11616c696365404558414d504c452e434f4d047961726e008a0198edf960008a01991205e4002a01";
    private static final String IDENT2_HEX =
        "1ad181d0b5d180d0b2d0b8d1812f686f7374405245414c4d2e52551a726d2f726d2e6578616d706c652e636f6d"
            + "405245414c4d2e52550970726f7879557365728a018bcfe5687b8a018bf3f1edc88d01e24007";

    @Test
    public void testVLongGoldenVectors() throws IOException {
        for (Map.Entry<Long, String> vector : VLONG_VECTORS.entrySet()) {
            long value = vector.getKey();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DelegationTokenIdentifier.writeVLong(new DataOutputStream(buffer), value);
            assertEquals(vector.getValue(), hex(buffer.toByteArray()), "encoding of " + value);
            assertEquals(value, DelegationTokenIdentifier.readVLong(input(vector.getValue())), "decoding of " + value);
        }
    }

    @Test
    public void testVIntGoldenVectors() throws IOException {
        for (Map.Entry<Integer, String> vector : VINT_VECTORS.entrySet()) {
            int value = vector.getKey();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DelegationTokenIdentifier.writeVInt(new DataOutputStream(buffer), value);
            assertEquals(vector.getValue(), hex(buffer.toByteArray()), "encoding of " + value);
            assertEquals(value, DelegationTokenIdentifier.readVInt(input(vector.getValue())), "decoding of " + value);
        }
    }

    @Test
    public void testTextGoldenVectors() throws IOException {
        for (Map.Entry<String, String> vector : TEXT_VECTORS.entrySet()) {
            String value = vector.getKey();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DelegationTokenIdentifier.writeText(new DataOutputStream(buffer), value);
            assertEquals(vector.getValue(), hex(buffer.toByteArray()), "encoding of '" + value + "'");
            assertEquals(value, DelegationTokenIdentifier.readText(input(vector.getValue())), "decoding of '" + value + "'");
        }
    }

    @Test
    public void testIdentifierGoldenVectors() throws IOException {
        DelegationTokenIdentifier ident1 = new DelegationTokenIdentifier(
            "alice@EXAMPLE.COM", "yarn", "", 1756339200000L, 1756944000000L, 42, 1);
        assertEquals(IDENT1_HEX, hex(ident1.toBytes()));
        assertEquals(ident1, DelegationTokenIdentifier.fromBytes(ident1.toBytes()));

        DelegationTokenIdentifier ident2 = new DelegationTokenIdentifier(
            "сервис/host@REALM.RU", "rm/rm.example.com@REALM.RU", "proxyUser",
            1700000000123L, 1700604800456L, 123456, 7);
        assertEquals(IDENT2_HEX, hex(ident2.toBytes()));
        assertEquals(ident2, DelegationTokenIdentifier.fromBytes(ident2.toBytes()));
    }

    @Test
    public void testRoundTripBoundaryValues() throws IOException {
        long[] dates = {0L, 1L, Long.MAX_VALUE, 1756339200000L};
        int[] numbers = {0, 1, 127, 128, Integer.MAX_VALUE};
        for (long date : dates) {
            for (int number : numbers) {
                DelegationTokenIdentifier ident = new DelegationTokenIdentifier(
                    "owner@R", "renewer", "real", date, date, number, number);
                assertEquals(ident, DelegationTokenIdentifier.fromBytes(ident.toBytes()));
            }
        }
    }

    @Test
    public void testNullRenewerAndRealUserNormalizedToEmpty() throws IOException {
        DelegationTokenIdentifier ident = new DelegationTokenIdentifier("alice", null, null, 1L, 2L, 3, 4);
        assertEquals("", ident.getRenewer());
        assertEquals("", ident.getRealUser());
        assertEquals(ident, DelegationTokenIdentifier.fromBytes(ident.toBytes()));
    }

    @Test
    public void testEmptyOwnerRejected() {
        assertThrows(IllegalArgumentException.class,
            () -> new DelegationTokenIdentifier("", "r", "", 1L, 2L, 3, 4));
        // Encoded form of an identifier with all-empty text fields.
        byte[] emptyOwner = bytes("000000000000");
        assertThrows(IOException.class, () -> DelegationTokenIdentifier.fromBytes(emptyOwner));
    }

    @Test
    public void testTrailingBytesRejected() {
        DelegationTokenIdentifier ident = new DelegationTokenIdentifier("alice", "bob", "", 1L, 2L, 3, 4);
        byte[] encoded = ident.toBytes();
        byte[] padded = Arrays.copyOf(encoded, encoded.length + 1);
        assertThrows(IOException.class, () -> DelegationTokenIdentifier.fromBytes(padded));
    }

    @Test
    public void testTruncatedBufferRejected() {
        DelegationTokenIdentifier ident = new DelegationTokenIdentifier("alice", "bob", "", 1L, 2L, 3, 4);
        byte[] encoded = ident.toBytes();
        byte[] truncated = Arrays.copyOf(encoded, encoded.length - 1);
        assertThrows(EOFException.class, () -> DelegationTokenIdentifier.fromBytes(truncated));
        assertThrows(EOFException.class, () -> DelegationTokenIdentifier.fromBytes(new byte[0]));
    }

    @Test
    public void testNegativeTextLengthRejected() {
        assertThrows(IOException.class, () -> DelegationTokenIdentifier.readText(input("ff")));
    }

    @Test
    public void testVIntOverflowRejected() throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DelegationTokenIdentifier.writeVLong(new DataOutputStream(buffer), 1L << 40);
        byte[] tooLong = buffer.toByteArray();
        assertThrows(IOException.class,
            () -> DelegationTokenIdentifier.readVInt(new DataInputStream(new ByteArrayInputStream(tooLong))));
    }

    private static DataInputStream input(String hexString) {
        return new DataInputStream(new ByteArrayInputStream(bytes(hexString)));
    }

    private static byte[] bytes(String hexString) {
        byte[] result = new byte[hexString.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hexString.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static String hex(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (byte b : data) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

}
