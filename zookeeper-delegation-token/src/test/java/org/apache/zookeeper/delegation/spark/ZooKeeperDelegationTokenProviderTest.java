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

package org.apache.zookeeper.delegation.spark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ServiceLoader;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.token.Token;
import org.apache.spark.SparkConf;
import org.apache.spark.security.HadoopDelegationTokenProvider;
import org.apache.zookeeper.delegation.ZooKeeperDelegationTokenIdentifier;
import org.apache.zookeeper.server.token.DelegationTokenSecretManager;
import org.apache.zookeeper.test.SaslAuthDigestTestBase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import scala.Option;

public class ZooKeeperDelegationTokenProviderTest extends SaslAuthDigestTestBase {

    private static final String LOGIN_MODULE = "org.apache.zookeeper.server.auth.DigestLoginModule";

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        File tmpDir = createTmpDir();
        File secretFile = new File(tmpDir, "master.key");
        Files.write(secretFile.toPath(), "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8));

        File jaasFile = new File(tmpDir, "jaas.conf");
        try (FileWriter writer = new FileWriter(jaasFile)) {
            writer.write(""
                + "Server {\n"
                + "    " + LOGIN_MODULE + " required\n"
                + "    user_alice=\"alicepass\";\n"
                + "};\n"
                + "Client {\n"
                + "    " + LOGIN_MODULE + " required\n"
                + "    username=\"alice\"\n"
                + "    password=\"alicepass\";\n"
                + "};\n");
        }

        System.setProperty("zookeeper.authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider");
        System.setProperty("java.security.auth.login.config", jaasFile.getAbsolutePath());
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED, "true");
        System.setProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE, secretFile.getAbsolutePath());
    }

    @AfterAll
    public static void tearDownAfterClass() {
        System.clearProperty("zookeeper.authProvider.1");
        System.clearProperty("java.security.auth.login.config");
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_ENABLED);
        System.clearProperty(DelegationTokenSecretManager.TOKEN_AUTH_SECRET_FILE);
    }

    @Test
    public void testProviderRegisteredViaServiceLoader() {
        boolean found = false;
        for (HadoopDelegationTokenProvider provider : ServiceLoader.load(HadoopDelegationTokenProvider.class)) {
            if (provider instanceof ZooKeeperDelegationTokenProvider) {
                found = true;
            }
        }
        assertTrue(found, "provider must be discoverable via ServiceLoader");
    }

    @Test
    public void testTokensRequiredOnlyWithQuorumConf() {
        ZooKeeperDelegationTokenProvider provider = new ZooKeeperDelegationTokenProvider();
        assertEquals("zookeeper", provider.serviceName());
        SparkConf sparkConf = new SparkConf(false);
        assertFalse(provider.delegationTokensRequired(sparkConf, new Configuration(false)));
        sparkConf.set(ZooKeeperDelegationTokenProvider.QUORUM_CONF, hostPort);
        assertTrue(provider.delegationTokensRequired(sparkConf, new Configuration(false)));
    }

    @Test
    public void testObtainDelegationTokensFilesTokenIntoCredentials() throws Exception {
        ZooKeeperDelegationTokenProvider provider = new ZooKeeperDelegationTokenProvider();
        SparkConf sparkConf = new SparkConf(false)
            .set(ZooKeeperDelegationTokenProvider.QUORUM_CONF, hostPort)
            .set(ZooKeeperDelegationTokenProvider.RENEWER_CONF, "yarn-rm")
            .set(ZooKeeperDelegationTokenProvider.SERVICE_CONF, "my-zk");

        Credentials credentials = new Credentials();
        Option<Object> renewalTime = provider.obtainDelegationTokens(new Configuration(false), sparkConf, credentials);

        assertTrue(renewalTime.isDefined());
        assertTrue((Long) renewalTime.get() > System.currentTimeMillis());

        Token<?> token = credentials.getToken(new org.apache.hadoop.io.Text("my-zk"));
        assertNotNull(token);
        assertEquals(ZooKeeperDelegationTokenIdentifier.KIND_NAME, token.getKind());
        ZooKeeperDelegationTokenIdentifier ident =
            (ZooKeeperDelegationTokenIdentifier) token.decodeIdentifier();
        assertEquals("alice", ident.getOwner().toString());
        assertEquals("yarn-rm", ident.getRenewer().toString());
    }

}
