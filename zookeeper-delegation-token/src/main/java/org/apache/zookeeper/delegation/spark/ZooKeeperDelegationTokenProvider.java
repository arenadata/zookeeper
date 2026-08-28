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

import java.io.IOException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.spark.SparkConf;
import org.apache.spark.security.HadoopDelegationTokenProvider;
import org.apache.zookeeper.delegation.ZooKeeperDelegationTokens;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scala.Option;

/**
 * Spark delegation token provider for ZooKeeper, discovered via
 * ServiceLoader. When {@code spark.zookeeper.quorum} is set, spark-submit
 * (running with a TGT or keytab and an ambient ZooKeeper client SASL
 * configuration) obtains a delegation token and files it into the job
 * credentials, from where it travels to executors and is renewed by the
 * usual Spark/YARN machinery.
 */
public class ZooKeeperDelegationTokenProvider implements HadoopDelegationTokenProvider {

    public static final String QUORUM_CONF = "spark.zookeeper.quorum";
    public static final String RENEWER_CONF = "spark.zookeeper.token.renewer";
    public static final String SERVICE_CONF = "spark.zookeeper.token.service";

    private static final Logger LOG = LoggerFactory.getLogger(ZooKeeperDelegationTokenProvider.class);

    @Override
    public String serviceName() {
        return "zookeeper";
    }

    @Override
    public boolean delegationTokensRequired(SparkConf sparkConf, Configuration hadoopConf) {
        return sparkConf.contains(QUORUM_CONF);
    }

    @Override
    public Option<Object> obtainDelegationTokens(Configuration hadoopConf, SparkConf sparkConf, Credentials creds) {
        String quorum = sparkConf.get(QUORUM_CONF);
        String renewer = sparkConf.get(RENEWER_CONF, "");
        String service = sparkConf.get(SERVICE_CONF, quorum);
        try {
            ZooKeeperDelegationTokens.ObtainedToken obtained =
                ZooKeeperDelegationTokens.obtainToken(quorum, renewer, 0, service);
            creds.addToken(new Text(service), obtained.getToken());
            LOG.info("Obtained ZooKeeper delegation token from {} as service {}", quorum, service);
            return Option.apply(obtained.getExpiryTime());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.warn("Interrupted while obtaining a ZooKeeper delegation token from {}", quorum, e);
            return Option.empty();
        } catch (IOException e) {
            LOG.warn("Failed to obtain a ZooKeeper delegation token from {}", quorum, e);
            return Option.empty();
        }
    }

}
