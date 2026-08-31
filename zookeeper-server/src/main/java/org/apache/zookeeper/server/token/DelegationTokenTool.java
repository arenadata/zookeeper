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
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.Watcher.Event.KeeperState;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.proto.GetDelegationTokenResponse;

/**
 * Delegation token generator.
 *
 * <p>The primary mode ({@code --server}) connects to the ensemble as a SASL
 * client (JAAS configuration comes from the environment, like any ZooKeeper
 * client) and requests a live token via getDelegationToken. The offline mode
 * ({@code --secret-file}) derives a token directly from the master key; such
 * a token is absent from the replicated store and is rejected by servers, so
 * it is useful only for diagnostics.
 */
public class DelegationTokenTool {

    private static final long DEFAULT_OFFLINE_MAX_LIFETIME_MS = 7L * 24 * 60 * 60 * 1000;
    private static final int CONNECT_TIMEOUT_SECONDS = 30;

    private DelegationTokenTool() {
    }

    public static void main(String[] args) {
        try {
            run(args, System.out);
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            usage(System.err);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("token generation failed: " + e.getMessage());
            System.exit(2);
        }
    }

    public static void run(String[] args, PrintStream out) throws IOException {
        String server = null;
        String secretFile = null;
        String owner = null;
        String renewer = "";
        String realUser = "";
        long maxLifetimeMs = -1;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
            case "--server":
                server = argValue(args, ++i, arg);
                break;
            case "--secret-file":
                secretFile = argValue(args, ++i, arg);
                break;
            case "--owner":
                owner = argValue(args, ++i, arg);
                break;
            case "--renewer":
                renewer = argValue(args, ++i, arg);
                break;
            case "--real-user":
                realUser = argValue(args, ++i, arg);
                break;
            case "--max-lifetime":
                maxLifetimeMs = parseDuration(argValue(args, ++i, arg));
                break;
            default:
                throw new IllegalArgumentException("unknown option: " + arg);
            }
        }
        if ((server == null) == (secretFile == null)) {
            throw new IllegalArgumentException("exactly one of --server or --secret-file is required");
        }
        if (server != null) {
            issueOnline(server, renewer, Math.max(maxLifetimeMs, 0), out);
        } else {
            issueOffline(secretFile, owner, renewer, realUser,
                maxLifetimeMs < 0 ? DEFAULT_OFFLINE_MAX_LIFETIME_MS : maxLifetimeMs, out);
        }
    }

    private static void issueOnline(String connectString, String renewer, long maxLifetimeMs, PrintStream out) throws IOException {
        CountDownLatch connected = new CountDownLatch(1);
        ZooKeeper zk = new ZooKeeper(connectString, 30000, event -> {
            if (event.getState() == KeeperState.SyncConnected) {
                connected.countDown();
            }
        });
        try {
            if (!connected.await(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IOException("timed out connecting to " + connectString);
            }
            GetDelegationTokenResponse token = zk.getDelegationToken(renewer, maxLifetimeMs);
            printToken(out, token.getIdentifier(), token.getPassword(), token.getExpiryTime());
        } catch (KeeperException e) {
            throw new IOException("token request failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while talking to " + connectString, e);
        } finally {
            try {
                zk.close();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static void issueOffline(
        String secretFile,
        String owner,
        String renewer,
        String realUser,
        long maxLifetimeMs,
        PrintStream out) throws IOException {
        if (owner == null || owner.isEmpty()) {
            throw new IllegalArgumentException("--owner is required with --secret-file");
        }
        DelegationTokenSecretManager manager =
            new DelegationTokenSecretManager(DelegationTokenSecretManager.readSecretFile(secretFile));
        long issueDate = System.currentTimeMillis();
        int sequenceNumber = new SecureRandom().nextInt(Integer.MAX_VALUE);
        DelegationTokenIdentifier ident = new DelegationTokenIdentifier(
            owner, renewer, realUser, issueDate, issueDate + maxLifetimeMs, sequenceNumber, 1);
        byte[] identifierBytes = ident.toBytes();
        System.err.println("WARNING: an offline token is absent from the server token store"
            + " and will be rejected by servers; use --server to issue a live token.");
        printToken(out, identifierBytes, manager.computePassword(identifierBytes), null);
    }

    private static void printToken(PrintStream out, byte[] identifierBytes, byte[] password, Long expiryTime) throws IOException {
        DelegationTokenIdentifier ident = DelegationTokenIdentifier.fromBytes(identifierBytes);
        String identifierB64 = Base64.getEncoder().encodeToString(identifierBytes);
        String passwordB64 = Base64.getEncoder().encodeToString(password);

        out.println("Kind:       " + DelegationTokenIdentifier.KIND);
        out.println("Identifier: " + identifierB64);
        out.println("Password:   " + passwordB64);
        out.println("Owner:      " + ident.getOwner());
        out.println("Renewer:    " + ident.getRenewer());
        out.println("MaxDate:    " + ident.getMaxDate());
        if (expiryTime != null) {
            out.println("Expiry:     " + expiryTime);
        }
        out.println();
        out.println("JAAS client section:");
        out.println("Client {");
        out.println("    org.apache.zookeeper.server.auth.DigestLoginModule required");
        out.println("    username=\"" + identifierB64 + "\"");
        out.println("    password=\"" + passwordB64 + "\";");
        out.println("};");
    }

    private static String argValue(String[] args, int index, String option) {
        if (index >= args.length) {
            throw new IllegalArgumentException(option + " requires a value");
        }
        return args[index];
    }

    /**
     * Parses a duration like 7d, 24h, 30m, 60s or plain milliseconds.
     */
    static long parseDuration(String value) {
        long multiplier;
        char unit = value.isEmpty() ? '?' : value.charAt(value.length() - 1);
        switch (unit) {
        case 'd':
            multiplier = 24L * 60 * 60 * 1000;
            break;
        case 'h':
            multiplier = 60L * 60 * 1000;
            break;
        case 'm':
            multiplier = 60L * 1000;
            break;
        case 's':
            multiplier = 1000L;
            break;
        default:
            multiplier = 0;
            break;
        }
        try {
            if (multiplier == 0) {
                return Long.parseLong(value);
            }
            return Long.parseLong(value.substring(0, value.length() - 1)) * multiplier;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid duration: " + value);
        }
    }

    private static void usage(PrintStream out) {
        out.println("usage: zkTokenTool.sh --server <connect-string> [--renewer <principal>] [--max-lifetime <7d|24h|30m|60s|millis>]");
        out.println("       zkTokenTool.sh --secret-file <path> --owner <principal>"
            + " [--renewer <principal>] [--real-user <principal>] [--max-lifetime <...>]   (diagnostics only)");
    }

}
