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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Identifier of a ZooKeeper delegation token.
 *
 * <p>The binary layout is byte-compatible with the Writable encoding of Hadoop's
 * {@code AbstractDelegationTokenIdentifier}: Text owner, Text renewer, Text realUser,
 * vlong issueDate, vlong maxDate, vint sequenceNumber, vint masterKeyId. This lets
 * external tooling wrap the identifier into a Hadoop {@code Token} without re-encoding,
 * while the ZooKeeper core stays free of hadoop-common dependencies.
 */
public class DelegationTokenIdentifier {

    public static final String KIND = "ZOOKEEPER_DELEGATION_TOKEN";

    /** Version byte written by Hadoop {@code AbstractDelegationTokenIdentifier}. */
    private static final byte VERSION = 0;

    /** Maximum encoded string length, same as Hadoop {@code Text.DEFAULT_MAX_LEN}. */
    private static final int MAX_TEXT_LENGTH = 1024 * 1024;

    private final String owner;
    private final String renewer;
    private final String realUser;
    private final long issueDate;
    private final long maxDate;
    private final int sequenceNumber;
    private final int masterKeyId;

    public DelegationTokenIdentifier(
        String owner,
        String renewer,
        String realUser,
        long issueDate,
        long maxDate,
        int sequenceNumber,
        int masterKeyId) {
        if (owner == null || owner.isEmpty()) {
            throw new IllegalArgumentException("token owner must not be empty");
        }
        this.owner = owner;
        this.renewer = renewer == null ? "" : renewer;
        this.realUser = realUser == null ? "" : realUser;
        this.issueDate = issueDate;
        this.maxDate = maxDate;
        this.sequenceNumber = sequenceNumber;
        this.masterKeyId = masterKeyId;
    }

    public String getOwner() {
        return owner;
    }

    public String getRenewer() {
        return renewer;
    }

    public String getRealUser() {
        return realUser;
    }

    public long getIssueDate() {
        return issueDate;
    }

    public long getMaxDate() {
        return maxDate;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public int getMasterKeyId() {
        return masterKeyId;
    }

    /**
     * Serializes this identifier into the Hadoop-compatible Writable form.
     */
    public byte[] toBytes() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);
        try {
            out.writeByte(VERSION);
            writeText(out, owner);
            writeText(out, renewer);
            writeText(out, realUser);
            writeVLong(out, issueDate);
            writeVLong(out, maxDate);
            writeVInt(out, sequenceNumber);
            writeVInt(out, masterKeyId);
        } catch (IOException e) {
            throw new IllegalStateException("in-memory serialization failed", e);
        }
        return buffer.toByteArray();
    }

    /**
     * Parses an identifier from its Writable form. The parse is strict: the whole
     * buffer must be consumed and the owner must be non-empty, so arbitrary
     * usernames do not accidentally decode into a valid identifier.
     *
     * @throws IOException if the buffer is not a well-formed identifier
     */
    public static DelegationTokenIdentifier fromBytes(byte[] data) throws IOException {
        ByteArrayInputStream buffer = new ByteArrayInputStream(data);
        DataInputStream in = new DataInputStream(buffer);
        byte version = in.readByte();
        if (version != VERSION) {
            throw new IOException("unknown token identifier version: " + version);
        }
        String owner = readText(in);
        String renewer = readText(in);
        String realUser = readText(in);
        long issueDate = readVLong(in);
        long maxDate = readVLong(in);
        int sequenceNumber = readVInt(in);
        int masterKeyId = readVInt(in);
        if (buffer.available() != 0) {
            throw new IOException("trailing bytes after token identifier");
        }
        if (owner.isEmpty()) {
            throw new IOException("token identifier has empty owner");
        }
        return new DelegationTokenIdentifier(owner, renewer, realUser, issueDate, maxDate, sequenceNumber, masterKeyId);
    }

    // vint/vlong follow the format of Hadoop WritableUtils: values in [-112, 127]
    // take one byte; otherwise the first byte encodes sign and byte count.

    static void writeVLong(DataOutput out, long value) throws IOException {
        if (value >= -112 && value <= 127) {
            out.writeByte((byte) value);
            return;
        }
        int firstByte = -112;
        if (value < 0) {
            value ^= -1L;
            firstByte = -120;
        }
        long tmp = value;
        while (tmp != 0) {
            tmp = tmp >> 8;
            firstByte--;
        }
        out.writeByte((byte) firstByte);
        int length = (firstByte < -120) ? -(firstByte + 120) : -(firstByte + 112);
        for (int idx = length; idx != 0; idx--) {
            int shiftBits = (idx - 1) * 8;
            long mask = 0xFFL << shiftBits;
            out.writeByte((byte) ((value & mask) >> shiftBits));
        }
    }

    static long readVLong(DataInput in) throws IOException {
        byte firstByte = in.readByte();
        int length = decodeVIntSize(firstByte);
        if (length == 1) {
            return firstByte;
        }
        long value = 0;
        for (int idx = 0; idx < length - 1; idx++) {
            byte b = in.readByte();
            value = value << 8;
            value = value | (b & 0xFF);
        }
        return isNegativeVInt(firstByte) ? (value ^ -1L) : value;
    }

    static void writeVInt(DataOutput out, int value) throws IOException {
        writeVLong(out, value);
    }

    static int readVInt(DataInput in) throws IOException {
        long value = readVLong(in);
        if (value > Integer.MAX_VALUE || value < Integer.MIN_VALUE) {
            throw new IOException("vint value out of integer range: " + value);
        }
        return (int) value;
    }

    private static int decodeVIntSize(byte value) {
        if (value >= -112) {
            return 1;
        } else if (value < -120) {
            return -119 - value;
        }
        return -111 - value;
    }

    private static boolean isNegativeVInt(byte value) {
        return value < -120 || (value >= -112 && value < 0);
    }

    static void writeText(DataOutput out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeVInt(out, bytes.length);
        out.write(bytes);
    }

    static String readText(DataInput in) throws IOException {
        int length = readVInt(in);
        if (length < 0 || length > MAX_TEXT_LENGTH) {
            throw new IOException("invalid text length: " + length);
        }
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DelegationTokenIdentifier)) {
            return false;
        }
        DelegationTokenIdentifier that = (DelegationTokenIdentifier) o;
        return issueDate == that.issueDate
            && maxDate == that.maxDate
            && sequenceNumber == that.sequenceNumber
            && masterKeyId == that.masterKeyId
            && owner.equals(that.owner)
            && renewer.equals(that.renewer)
            && realUser.equals(that.realUser);
    }

    @Override
    public int hashCode() {
        return Objects.hash(owner, renewer, realUser, issueDate, maxDate, sequenceNumber, masterKeyId);
    }

    @Override
    public String toString() {
        return "DelegationTokenIdentifier(owner=" + owner
            + ", renewer=" + renewer
            + ", realUser=" + realUser
            + ", issueDate=" + issueDate
            + ", maxDate=" + maxDate
            + ", sequenceNumber=" + sequenceNumber
            + ", masterKeyId=" + masterKeyId + ")";
    }

}
