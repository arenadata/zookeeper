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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class RestCfgTest {

    private RestCfg cfg(String properties) throws IOException {
        return new RestCfg(new ByteArrayInputStream(properties.getBytes()));
    }

    @Test
    public void testKerberosSettingsAreAbsentByDefault() throws IOException {
        RestCfg cfg = cfg("rest.port=9998\n");
        assertNull(cfg.getSpnegoPrincipal());
        assertNull(cfg.getSpnegoKeytab());
        assertNull(cfg.getZkPrincipal());
        assertNull(cfg.getZkKeytab());
        assertEquals(0, cfg.kerberosConfigErrors().size());
    }

    @Test
    public void testKerberosSettingsAreRead() throws IOException {
        RestCfg cfg = cfg("rest.spnego.principal=HTTP/host@REALM\n"
                + "rest.spnego.keytab=/etc/keytab\n"
                + "rest.zk.principal=zk-rest/host@REALM\n"
                + "rest.zk.keytab=/etc/zk.keytab\n");
        assertEquals("HTTP/host@REALM", cfg.getSpnegoPrincipal());
        assertEquals("/etc/keytab", cfg.getSpnegoKeytab());
        assertEquals("zk-rest/host@REALM", cfg.getZkPrincipal());
        assertEquals("/etc/zk.keytab", cfg.getZkKeytab());
    }

    @Test
    public void testHostPatternIsResolvedAgainstTheLocalHost() throws IOException {
        RestCfg cfg = cfg("rest.spnego.principal=HTTP/_HOST@REALM\n"
                + "rest.spnego.keytab=/etc/keytab\n"
                + "rest.zk.principal=zk-rest/_HOST\n");
        String localHost = cfg.getSpnegoPrincipal();
        assertTrue(localHost.startsWith("HTTP/") && localHost.endsWith("@REALM"),
                localHost);
        assertTrue(!localHost.contains("_HOST"), localHost);
        assertTrue(cfg.getZkPrincipal().startsWith("zk-rest/"), cfg.getZkPrincipal());
    }

    @Test
    public void testSubstituteHostReplacesTheInstanceOnly() {
        assertEquals("HTTP/h.example.com@CORP_HOSTS.COM",
                RestCfg.substituteHost("HTTP/_HOST@CORP_HOSTS.COM", "h.example.com"));
        assertEquals("HTTP/h.example.com", RestCfg.substituteHost("HTTP/_HOST", "h.example.com"));
        assertEquals("HTTP/vault@EU_HOSTING.EXAMPLE",
                RestCfg.substituteHost("HTTP/vault@EU_HOSTING.EXAMPLE", "h"));
        assertEquals("HTTP@_HOST", RestCfg.substituteHost("HTTP@_HOST", "h"));
    }

    @Test
    public void testPrincipalWithoutKeytabIsAnError() throws IOException {
        RestCfg cfg = cfg("rest.spnego.principal=HTTP/host@REALM\n");
        List<String> errors = cfg.kerberosConfigErrors();
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).contains("rest.spnego.keytab"), errors.toString());
    }

    @Test
    public void testKeytabWithoutPrincipalIsAnError() throws IOException {
        RestCfg cfg = cfg("rest.zk.keytab=/etc/zk.keytab\n");
        List<String> errors = cfg.kerberosConfigErrors();
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).contains("rest.zk.principal"), errors.toString());
    }

    @Test
    public void testMissingKeytabFileIsAnError(@TempDir File tempDir) throws IOException {
        File keytab = new File(tempDir, "missing.keytab");
        RestCfg cfg = cfg("rest.spnego.principal=HTTP/host@REALM\n"
                + "rest.spnego.keytab=" + keytab.getAbsolutePath() + "\n"
                + "rest.zk.principal=zk-rest/host@REALM\n"
                + "rest.zk.keytab=/no/such/file.keytab\n");
        List<String> errors = cfg.kerberosConfigErrors();
        assertEquals(2, errors.size());
        assertTrue(errors.get(0).contains(keytab.getName()), errors.toString());
        assertTrue(errors.get(1).contains("/no/such/file.keytab"), errors.toString());
    }

    @Test
    public void testExistingKeytabFilePassesValidation(@TempDir File tempDir) throws IOException {
        File keytab = Files.createFile(new File(tempDir, "rest.keytab").toPath()).toFile();
        RestCfg cfg = cfg("rest.spnego.principal=HTTP/host@REALM\n"
                + "rest.spnego.keytab=" + keytab.getAbsolutePath() + "\n");
        assertEquals(0, cfg.kerberosConfigErrors().size());
    }

    @Test
    public void testBlankValuesAreTreatedAsAbsent() throws IOException {
        RestCfg cfg = cfg("rest.spnego.principal=  \n"
                + "rest.zk.keytab=  \n");
        assertNull(cfg.getSpnegoPrincipal());
        assertNull(cfg.getZkKeytab());
        assertEquals(0, cfg.kerberosConfigErrors().size());
    }

    @Test
    public void testKeytabValueIsTrimmed(@TempDir File tempDir) throws IOException {
        File keytab = Files.createFile(new File(tempDir, "rest.keytab").toPath()).toFile();
        RestCfg cfg = cfg("rest.spnego.principal=HTTP/host@REALM\n"
                + "rest.spnego.keytab=" + keytab.getAbsolutePath() + "  \n");
        assertEquals(keytab.getAbsolutePath(), cfg.getSpnegoKeytab());
        assertEquals(0, cfg.kerberosConfigErrors().size());
    }

    @Test
    public void testDirectoryKeytabIsAnError(@TempDir File tempDir) throws IOException {
        RestCfg cfg = cfg("rest.spnego.principal=HTTP/host@REALM\n"
                + "rest.spnego.keytab=" + tempDir.getAbsolutePath() + "\n");
        List<String> errors = cfg.kerberosConfigErrors();
        assertEquals(1, errors.size());
    }
}
