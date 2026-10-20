/**
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

package org.apache.zookeeper.server.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.Base64;
import org.junit.jupiter.api.Test;

public class AuthorizationHeaderTest {

    private static final String NEGOTIATE = "Negotiate";

    private static String negotiable(byte[] token) {
        return NEGOTIATE + " " + Base64.getEncoder().encodeToString(token);
    }

    @Test
    public void testSchemeMatchingIsCaseInsensitiveAndSpaceDelimited() {
        assertTrue(AuthorizationHeader.isScheme("Negotiate dGVzdA==", NEGOTIATE));
        assertTrue(AuthorizationHeader.isScheme("negotiate dGVzdA==", NEGOTIATE));
        assertTrue(AuthorizationHeader.isScheme("NEGOTIATE dGVzdA==", NEGOTIATE));
        assertFalse(AuthorizationHeader.isScheme(null, NEGOTIATE));
        assertFalse(AuthorizationHeader.isScheme("Negotiate", NEGOTIATE));
        assertFalse(AuthorizationHeader.isScheme("NegotiateX dGVzdA==", NEGOTIATE));
        assertFalse(AuthorizationHeader.isScheme("Basic dGVzdA==", NEGOTIATE));
        assertTrue(AuthorizationHeader.isScheme("Basic dGVzdA==", "Basic"));
    }

    @Test
    public void testCredentialsDecodeWithToleratedWhitespace() {
        assertArrayEquals(new byte[]{1, 2},
            AuthorizationHeader.schemeCredentials(negotiable(new byte[]{1, 2}), NEGOTIATE));
        assertArrayEquals(new byte[]{1, 2},
            AuthorizationHeader.schemeCredentials("negotiate "
                + Base64.getEncoder().encodeToString(new byte[]{1, 2}), NEGOTIATE));
        assertArrayEquals(new byte[]{1, 2},
            AuthorizationHeader.schemeCredentials("Negotiate  "
                + Base64.getEncoder().encodeToString(new byte[]{1, 2}), NEGOTIATE));
        assertArrayEquals(new byte[]{1, 2},
            AuthorizationHeader.schemeCredentials("Negotiate "
                + Base64.getEncoder().encodeToString(new byte[]{1, 2}) + " ", NEGOTIATE));
    }

    @Test
    public void testCredentialsNullForAbsentSchemeOrGarbage() {
        assertNull(AuthorizationHeader.schemeCredentials(null, NEGOTIATE));
        assertNull(AuthorizationHeader.schemeCredentials("Negotiate", NEGOTIATE));
        assertNull(AuthorizationHeader.schemeCredentials("Negotiate !!!not-base64!!!", NEGOTIATE));
        assertNull(AuthorizationHeader.schemeCredentials("Basic dGVzdA==", NEGOTIATE));
    }
}
