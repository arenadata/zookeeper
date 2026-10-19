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

package org.apache.zookeeper.server.jersey.cfg;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.apache.zookeeper.client.ZKClientConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The ZooKeeper client section of the JAAS configuration, served from the
 * gateway's principal and keytab instead of a JAAS file. Every other section
 * is delegated to the configuration that was installed before, so sections
 * brought in through {@code -Djava.security.auth.login.config} keep working;
 * an existing client section of that file is overridden.
 */
public class ZkClientJaasConfiguration extends Configuration {

    private static final Logger LOG = LoggerFactory.getLogger(ZkClientJaasConfiguration.class);

    private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";

    private final Configuration previous;
    private final String clientSection;
    private final String principal;
    private final String keytab;

    public ZkClientJaasConfiguration(Configuration previous, String principal, String keytab) {
        this.previous = previous;
        this.clientSection = System.getProperty(ZKClientConfig.LOGIN_CONTEXT_NAME_KEY,
                ZKClientConfig.LOGIN_CONTEXT_NAME_KEY_DEFAULT);
        this.principal = principal;
        this.keytab = keytab;
    }

    /**
     * Installs the wrapper as the JVM-wide configuration; the ZooKeeper
     * clients of the gateway pick it up on their first SASL login.
     */
    public static void install(String principal, String keytab) {
        ZkClientJaasConfiguration wrapper = new ZkClientJaasConfiguration(
                Configuration.getConfiguration(), principal, keytab);
        if (wrapper.previous.getAppConfigurationEntry(wrapper.clientSection) != null) {
            LOG.warn("Overriding JAAS section {} of the previous configuration "
                    + "with rest.zk.principal {}", wrapper.clientSection, principal);
        }
        Configuration.setConfiguration(wrapper);
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        if (name.equals(clientSection)) {
            return new AppConfigurationEntry[] {entry()};
        }
        return previous.getAppConfigurationEntry(name);
    }

    @Override
    public void refresh() {
        previous.refresh();
    }

    private AppConfigurationEntry entry() {
        Map<String, Object> options = new HashMap<>();
        options.put("useKeyTab", "true");
        options.put("keyTab", keytab);
        options.put("principal", principal);
        options.put("storeKey", "true");
        options.put("useTicketCache", "false");
        options.put("doNotPrompt", "true");
        options.put("refreshKrb5Config", "true");
        options.put("isInitiator", "true");
        return new AppConfigurationEntry(KRB5_LOGIN_MODULE,
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
    }
}
