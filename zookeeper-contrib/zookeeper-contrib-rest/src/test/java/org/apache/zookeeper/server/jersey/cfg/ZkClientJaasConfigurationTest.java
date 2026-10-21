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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.apache.zookeeper.client.ZKClientConfig;
import org.apache.zookeeper.common.vault.VaultCredentialProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

public class ZkClientJaasConfigurationTest {

    private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";

    private final String clientSection = ZKClientConfig.LOGIN_CONTEXT_NAME_KEY_DEFAULT;

    @AfterEach
    public void clearSectionOverrides() {
        System.clearProperty(ZKClientConfig.LOGIN_CONTEXT_NAME_KEY);
        System.clearProperty(VaultCredentialProvider.KERBEROS_LOGIN_CONTEXT);
    }

    private ZkClientJaasConfiguration wrapper(Configuration previous) {
        return new ZkClientJaasConfiguration(previous, "zk-rest/host@REALM", "/etc/keytab");
    }

    private static Configuration section(String name, String loginModule) {
        Map<String, Object> options = new HashMap<>();
        AppConfigurationEntry entry = new AppConfigurationEntry(loginModule,
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String section) {
                return section.equals(name) ? new AppConfigurationEntry[] {entry} : null;
            }
        };
    }

    @Test
    public void testServesKrb5LoginModuleForTheClientSection() {
        AppConfigurationEntry[] entries = wrapper(section("Other", "some.Module"))
                .getAppConfigurationEntry(clientSection);
        assertEquals(1, entries.length);
        assertEquals(KRB5_LOGIN_MODULE, entries[0].getLoginModuleName());
        assertEquals(AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                entries[0].getControlFlag());
        Map<String, ?> options = entries[0].getOptions();
        assertEquals("true", options.get("useKeyTab"));
        assertEquals("/etc/keytab", options.get("keyTab"));
        assertEquals("zk-rest/host@REALM", options.get("principal"));
        assertEquals("true", options.get("storeKey"));
        assertEquals("true", options.get("isInitiator"));
        assertEquals("true", options.get("doNotPrompt"));
        assertEquals("false", options.get("useTicketCache"));
    }

    @Test
    public void testDelegatesUnknownSectionsToThePreviousConfiguration() {
        Configuration previous = section("External", "some.Module");
        AppConfigurationEntry[] entries = wrapper(previous)
                .getAppConfigurationEntry("External");
        assertEquals(1, entries.length);
        assertEquals("some.Module", entries[0].getLoginModuleName());
        assertNull(wrapper(previous).getAppConfigurationEntry("Missing"));
    }

    @Test
    public void testOverridesAClientSectionOfThePreviousConfiguration() {
        Configuration previous = section(clientSection, "some.Module");
        AppConfigurationEntry[] entries = wrapper(previous)
                .getAppConfigurationEntry(clientSection);
        assertEquals(1, entries.length);
        assertEquals(KRB5_LOGIN_MODULE, entries[0].getLoginModuleName());
    }

    @Test
    public void testHonorsTheClientSectionNameOverride() {
        System.setProperty(ZKClientConfig.LOGIN_CONTEXT_NAME_KEY, "ZkRest");
        ZkClientJaasConfiguration wrapper = wrapper(section("Other", "some.Module"));
        assertNull(wrapper.getAppConfigurationEntry(clientSection));
        assertEquals(KRB5_LOGIN_MODULE,
                wrapper.getAppConfigurationEntry("ZkRest")[0].getLoginModuleName());
    }

    @Test
    public void testInstallReplacesTheGlobalConfigurationAndDelegates() {
        Configuration previous = Configuration.getConfiguration();
        Configuration inMemory = section("External", "some.Module");
        Configuration.setConfiguration(inMemory);
        try {
            ZkClientJaasConfiguration.install("zk-rest/host@REALM", "/etc/keytab");
            AppConfigurationEntry[] client = Configuration.getConfiguration()
                    .getAppConfigurationEntry(clientSection);
            assertEquals(KRB5_LOGIN_MODULE, client[0].getLoginModuleName());
            assertEquals("some.Module", Configuration.getConfiguration()
                    .getAppConfigurationEntry("External")[0].getLoginModuleName());
        } finally {
            Configuration.setConfiguration(previous);
        }
    }

    @Test
    public void testInstallDefaultsTheVaultLoginContextToTheClientSection() {
        Configuration previous = Configuration.getConfiguration();
        try {
            ZkClientJaasConfiguration.install("zk-rest/host@REALM", "/etc/keytab");
            assertEquals(clientSection,
                    System.getProperty(VaultCredentialProvider.KERBEROS_LOGIN_CONTEXT));
        } finally {
            Configuration.setConfiguration(previous);
        }
    }

    @Test
    public void testInstallKeepsAnExplicitVaultLoginContext() {
        Configuration previous = Configuration.getConfiguration();
        System.setProperty(VaultCredentialProvider.KERBEROS_LOGIN_CONTEXT, "VaultSection");
        try {
            ZkClientJaasConfiguration.install("zk-rest/host@REALM", "/etc/keytab");
            assertEquals("VaultSection",
                    System.getProperty(VaultCredentialProvider.KERBEROS_LOGIN_CONTEXT));
        } finally {
            Configuration.setConfiguration(previous);
        }
    }
}
