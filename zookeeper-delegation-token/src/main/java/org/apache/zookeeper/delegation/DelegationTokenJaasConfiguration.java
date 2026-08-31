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

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import org.apache.hadoop.security.token.Token;

/**
 * JAAS configuration that answers the ZooKeeper client section with the
 * delegation token credentials and delegates every other section to the
 * previously installed configuration.
 */
final class DelegationTokenJaasConfiguration extends Configuration {

    private final Configuration base;
    private final String clientSection;
    private final AppConfigurationEntry entry;

    DelegationTokenJaasConfiguration(Configuration base, String clientSection, String loginModule, Token<?> token) {
        this.base = base;
        this.clientSection = clientSection;
        Map<String, String> options = new HashMap<>();
        options.put("username", Base64.getEncoder().encodeToString(token.getIdentifier()));
        options.put("password", Base64.getEncoder().encodeToString(token.getPassword()));
        this.entry = new AppConfigurationEntry(
            loginModule, AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        if (clientSection.equals(name)) {
            return new AppConfigurationEntry[]{entry};
        }
        return base == null ? null : base.getAppConfigurationEntry(name);
    }

}
