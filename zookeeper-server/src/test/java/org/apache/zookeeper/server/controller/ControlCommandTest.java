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

package org.apache.zookeeper.server.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;

public class ControlCommandTest {

  @Test
  public void verifyGeneratedUri() {
    assertEquals("command/ping",
        ControlCommand.createCommandUri(ControlCommand.Action.PING, null).toLowerCase());
    assertEquals("command/ping",
        ControlCommand.createCommandUri(ControlCommand.Action.PING, "").toLowerCase());
    assertEquals("command/closeconnection/1234",
        ControlCommand.createCommandUri(ControlCommand.Action.CLOSECONNECTION,
            "1234").toLowerCase());
  }

  @Test
  public void verifyParseChecksForNull() {
    try {
      ControlCommand.parseUri(null);
      fail("Should have thrown for null.");
    } catch (IllegalArgumentException ex) {
    }
  }

  @Test
  public void verifyParseChecksForPrefix() {
    try {
      ControlCommand.parseUri("ping");
      fail("Should have thrown for missing command/ prefix.");
    } catch (IllegalArgumentException ex) {
    }
  }

  @Test
  public void verifyParseCorrectlyFindsCommandWithNoParameter() {
    assertEquals(ControlCommand.Action.PING,
        ControlCommand.parseUri("command/ping").getAction());
  }

  @Test
  public void verifyParseCorrectlyFindsCommandWithParameter() {
    ControlCommand command = ControlCommand.parseUri("command/closeconnection/1234");
    assertEquals(ControlCommand.Action.CLOSECONNECTION, command.getAction());
    assertEquals("1234", command.getParameter());
  }

  @Test
  public void verifyParseIllegalCommandWithNoParameter() {
    try {
      ControlCommand.parseUri("pings");
      fail("Should have thrown for non existing command.");
    } catch (IllegalArgumentException ex) {
    }
  }

  @Test
  public void verifyParseIllegalCommandWithParameter() {
    try {
      ControlCommand.parseUri("command/close_connection/1234");
      fail("Should have thrown for non existing command.");
    } catch (IllegalArgumentException ex) {
    }
  }
}
