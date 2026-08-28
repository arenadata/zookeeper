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

/**
 * Offline delegation token generator. Derives the token password from the
 * ensemble master key file, so a token minted here is accepted by any server
 * of the ensemble configured with the same key.
 */
public class DelegationTokenTool {

    private static final long DEFAULT_MAX_LIFETIME_MS = 7L * 24 * 60 * 60 * 1000;

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
            System.err.println("failed to read master key: " + e.getMessage());
            System.exit(2);
        }
    }

    public static void run(String[] args, PrintStream out) throws IOException {
        String secretFile = null;
        String owner = null;
        String renewer = "";
        String realUser = "";
        long maxLifetimeMs = DEFAULT_MAX_LIFETIME_MS;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
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
        if (secretFile == null) {
            throw new IllegalArgumentException("--secret-file is required");
        }
        if (owner == null || owner.isEmpty()) {
            throw new IllegalArgumentException("--owner is required");
        }

        DelegationTokenSecretManager manager =
            new DelegationTokenSecretManager(DelegationTokenSecretManager.readSecretFile(secretFile));

        long issueDate = System.currentTimeMillis();
        int sequenceNumber = new SecureRandom().nextInt(Integer.MAX_VALUE);
        DelegationTokenIdentifier ident = new DelegationTokenIdentifier(
            owner, renewer, realUser, issueDate, issueDate + maxLifetimeMs, sequenceNumber, 1);

        byte[] identifierBytes = ident.toBytes();
        String identifierB64 = Base64.getEncoder().encodeToString(identifierBytes);
        String passwordB64 = Base64.getEncoder().encodeToString(manager.computePassword(identifierBytes));

        out.println("Kind:       " + DelegationTokenIdentifier.KIND);
        out.println("Identifier: " + identifierB64);
        out.println("Password:   " + passwordB64);
        out.println("Owner:      " + ident.getOwner());
        out.println("Renewer:    " + ident.getRenewer());
        out.println("MaxDate:    " + ident.getMaxDate());
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
        out.println("usage: zkTokenTool.sh --secret-file <path> --owner <principal>"
            + " [--renewer <principal>] [--real-user <principal>] [--max-lifetime <7d|24h|30m|60s|millis>]");
    }

}
