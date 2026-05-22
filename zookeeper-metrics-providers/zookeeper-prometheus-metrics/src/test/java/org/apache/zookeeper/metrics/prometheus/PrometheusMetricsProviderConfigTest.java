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

package org.apache.zookeeper.metrics.prometheus;

import static org.junit.jupiter.api.Assertions.assertThrows;
import io.prometheus.client.CollectorRegistry;
import java.util.Properties;
import org.apache.zookeeper.metrics.MetricsProviderLifeCycleException;
import org.junit.jupiter.api.Test;


public class PrometheusMetricsProviderConfigTest {

    @Test
    public void testInvalidPort() {
        assertThrows(MetricsProviderLifeCycleException.class, () -> {
            CollectorRegistry.defaultRegistry.clear();
            PrometheusMetricsProvider provider = new PrometheusMetricsProvider();
            Properties configuration = new Properties();
            configuration.setProperty("httpPort", "65536");
            configuration.setProperty("exportJvmInfo", "false");
            provider.configure(configuration);
            provider.start();
        });
    }

    @Test
    public void testInvalidAddr() {
        assertThrows(MetricsProviderLifeCycleException.class, () -> {
            CollectorRegistry.defaultRegistry.clear();
            PrometheusMetricsProvider provider = new PrometheusMetricsProvider();
            Properties configuration = new Properties();
            configuration.setProperty("httpHost", "master");
            configuration.setProperty("exportJvmInfo", "false");
            provider.configure(configuration);
            provider.start();
        });
    }

    @Test
    public void testInvalidKeystoreLocation() {
        assertThrows(MetricsProviderLifeCycleException.class, () -> {
            CollectorRegistry.defaultRegistry.clear();
            PrometheusMetricsProvider provider = new PrometheusMetricsProvider();
            Properties configuration = new Properties();
            configuration.setProperty("ssl.enabled", "true");
            configuration.setProperty("ssl.keyStore.location", "");
            provider.configure(configuration);
        });
    }

    @Test
    public void testInvalidKeystorePassword() {
        assertThrows(MetricsProviderLifeCycleException.class, () -> {
            CollectorRegistry.defaultRegistry.clear();
            PrometheusMetricsProvider provider = new PrometheusMetricsProvider();
            Properties configuration = new Properties();
            configuration.setProperty("ssl.enabled", "true");
            configuration.setProperty("ssl.keyStore.location", "/tmp/key.jks");
            configuration.setProperty("ssl.keyStore.password", "");
            provider.configure(configuration);
        });
    }

    @Test
    public void testValidConfig() throws MetricsProviderLifeCycleException {
        CollectorRegistry.defaultRegistry.clear();
        PrometheusMetricsProvider provider = new PrometheusMetricsProvider();
        Properties configuration = new Properties();
        configuration.setProperty("httpHost", "0.0.0.0");
        configuration.setProperty("httpPort", "0");
        configuration.setProperty("exportJvmInfo", "false");
        provider.configure(configuration);
        try {
            provider.start();
        } finally {
            provider.stop();
        }
    }

}
