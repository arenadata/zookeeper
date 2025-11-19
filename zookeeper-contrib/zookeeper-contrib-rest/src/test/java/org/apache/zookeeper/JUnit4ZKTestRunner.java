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

package org.apache.zookeeper;

import java.lang.reflect.Method;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The sole responsibility of this class is to print to the log when a test
 * starts and when it finishes.
 */
public class JUnit4ZKTestRunner implements BeforeEachCallback, AfterEachCallback {

    private static final Logger LOG = LoggerFactory.getLogger(JUnit4ZKTestRunner.class);

    @Override
    public void beforeEach(ExtensionContext context) {
        String name = context.getDisplayName();
        LOG.info("RUNNING TEST METHOD {}", name);
    }

    @Override
    public void afterEach(ExtensionContext context) {
        String name = context.getDisplayName();
        if (context.getExecutionException().isPresent()) {
            LOG.warn("TEST METHOD FAILED {}", name, context.getExecutionException().get());
        } else {
            Runtime rt = Runtime.getRuntime();
            long usedKB = (rt.totalMemory() - rt.freeMemory()) / 1024;
            LOG.info("Memory used {}", usedKB);
            ThreadGroup tg = Thread.currentThread().getThreadGroup();
            while (tg.getParent() != null) {
                tg = tg.getParent();
            }
            LOG.info("Number of threads {}", tg.activeCount());
            LOG.info("FINISHED TEST METHOD {}", name);
        }
    }

}
