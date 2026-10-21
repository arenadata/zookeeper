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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.  See the License for the specific
 * language governing permissions and limitations under the License.
 */

package org.apache.zookeeper.server.jersey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;

import org.apache.zookeeper.server.jersey.cfg.RestCfg;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class RestMainConfigTest {

    @Test
    public void testConfigPathIsTakenFromTheFirstArgument(@TempDir File tempDir)
            throws IOException {
        File properties = new File(tempDir, "rest.properties");
        Files.write(properties.toPath(), "rest.port = 1234\n".getBytes());
        RestCfg cfg = RestMain.loadConfig(new String[] {properties.getAbsolutePath()});
        assertEquals(1234, cfg.getPort());
    }

    @Test
    public void testFallsBackToTheClasspathResourceWithoutArguments() throws IOException {
        assertEquals(4321, RestMain.loadConfig(new String[0]).getPort());
    }

    @Test
    public void testMissingConfigFileFailsFast() {
        assertThrows(FileNotFoundException.class,
                () -> RestMain.loadConfig(new String[] {"/no/such/rest.properties"}));
    }
}
