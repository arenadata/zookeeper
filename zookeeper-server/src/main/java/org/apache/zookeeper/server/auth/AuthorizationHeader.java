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

import java.util.Base64;

/**
 * Helpers for the HTTP Authorization header as RFC 7235 defines it: a
 * case-insensitive scheme token followed by a space and the credential.
 * Shared by the SPNEGO consumers (admin server command filter, REST
 * gateway) so scheme parsing cannot drift between them.
 */
public final class AuthorizationHeader {

    private AuthorizationHeader() {
    }

    /** True when the header carries the given scheme token. */
    public static boolean isScheme(String authorization, String scheme) {
        return authorization != null
                && authorization.length() > scheme.length()
                && authorization.regionMatches(true, 0, scheme, 0, scheme.length())
                && authorization.charAt(scheme.length()) == ' ';
    }

    /**
     * The base64-decoded credential of a header carrying the given scheme,
     * or null when the header is absent, uses another scheme, or the
     * credential is not valid base64. Whitespace around the credential is
     * tolerated.
     */
    public static byte[] schemeCredentials(String authorization, String scheme) {
        if (!isScheme(authorization, scheme)) {
            return null;
        }
        try {
            return Base64.getDecoder().decode(authorization.substring(scheme.length()).trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
