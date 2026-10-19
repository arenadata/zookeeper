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

package org.apache.zookeeper.server.jersey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.apache.zookeeper.server.jersey.cfg.RestCfg;
import org.junit.jupiter.api.Test;

public class RestMainZkJaasTest {

    private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";

    private RestCfg cfg(String properties) throws IOException {
        return new RestCfg(new ByteArrayInputStream(properties.getBytes()));
    }

    @Test
    public void testZkSettingsInstallTheClientJaasSection() throws IOException {
        Configuration previous = Configuration.getConfiguration();
        try {
            new RestMain(cfg("rest.zk.principal=zk-rest/host@REALM\n"
                    + "rest.zk.keytab=/etc/zk-rest.keytab\n"));
            AppConfigurationEntry[] client = Configuration.getConfiguration()
                    .getAppConfigurationEntry("Client");
            assertEquals(KRB5_LOGIN_MODULE, client[0].getLoginModuleName());
            assertEquals("zk-rest/host@REALM", client[0].getOptions().get("principal"));
            assertEquals("/etc/zk-rest.keytab", client[0].getOptions().get("keyTab"));
        } finally {
            Configuration.setConfiguration(previous);
        }
    }

    @Test
    public void testWithoutZkSettingsTheConfigurationIsUntouched() throws IOException {
        Configuration previous = Configuration.getConfiguration();
        new RestMain(cfg("rest.port=9998\n"));
        assertSame(previous, Configuration.getConfiguration());
    }
}
