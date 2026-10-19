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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

public class RestCfg {

   private static final String HOSTNAME_PATTERN = "_HOST";

   private Properties cfg = new Properties();

   private Set<Endpoint> endpoints = new HashSet<Endpoint>();
   private Credentials credentials = new Credentials();

   public RestCfg(String resource) throws IOException {
       this(RestCfg.class.getClassLoader().getResourceAsStream(resource));
   }

   public RestCfg(InputStream io) throws IOException {
     try {
       cfg.load(io);
       extractEndpoints();
       extractCredentials();
     } finally {
       io.close();
     }
   }

   private void extractCredentials() {
       if (cfg.containsKey("rest.http.auth")) {
           credentials = new Credentials(cfg.getProperty("rest.http.auth", ""));
       }
   }

   private void extractEndpoints() {
       int count = 1;
       while (true) {
           String e = cfg.getProperty(
                   String.format("rest.endpoint.%d", count), null);
           if (e == null) {
               break;
           }

           String[] parts = e.split(";");
           if (parts.length != 2) {
               count++;
               continue;
           }
           Endpoint point = new Endpoint(parts[0], parts[1]);
           
           String c = cfg.getProperty(String.format(
                   "rest.endpoint.%d.http.auth", count), "");
           point.setCredentials(c);
           
           String digest = cfg.getProperty(String.format(
                   "rest.endpoint.%d.zk.digest", count), "");
           point.setZooKeeperAuthInfo(digest);

           endpoints.add(point);
           count++;
       }
   }

   public int getPort() {
       return Integer.parseInt(cfg.getProperty("rest.port", "9998"));
   }

   public boolean useSSL() {
       return Boolean.valueOf(cfg.getProperty("rest.ssl", "false"));
   }

   public final Set<Endpoint> getEndpoints() {
       return endpoints;
   }

   public final Credentials getCredentials() {
       return credentials;
   }

   public String getJKS() {
       return cfg.getProperty("rest.ssl.jks");
   }

   public String getJKS(String def) {
       return cfg.getProperty("rest.ssl.jks", def);
   }

   public String getJKSPassword() {
       return cfg.getProperty("rest.ssl.jks.pass");
   }

   /**
    * The service principal the SPNEGO HTTP acceptor logs in as, with an
    * instance of {@code _HOST} replaced by the local host name.
    */
   public String getSpnegoPrincipal() {
       return resolveHostPattern(cfg.getProperty("rest.spnego.principal"));
   }

   public String getSpnegoKeytab() {
       return cfg.getProperty("rest.spnego.keytab");
   }

   /**
    * The principal the gateway itself logs in as for its ZooKeeper client
    * sessions, with an instance of {@code _HOST} replaced by the local host
    * name.
    */
   public String getZkPrincipal() {
       return resolveHostPattern(cfg.getProperty("rest.zk.principal"));
   }

   public String getZkKeytab() {
       return cfg.getProperty("rest.zk.keytab");
   }

   /**
    * Local problems that make the Kerberos settings unusable: a principal
    * without its keytab, the reverse, or a keytab file that cannot be read.
    */
   public List<String> kerberosConfigErrors() {
       List<String> errors = new ArrayList<>();
       checkKeytabPair("rest.spnego.principal", "rest.spnego.keytab",
               getSpnegoPrincipal(), getSpnegoKeytab(), errors);
       checkKeytabPair("rest.zk.principal", "rest.zk.keytab",
               getZkPrincipal(), getZkKeytab(), errors);
       return errors;
   }

   private static void checkKeytabPair(String principalKey, String keytabKey,
           String principal, String keytab, List<String> errors) {
       boolean hasPrincipal = principal != null && !principal.trim().isEmpty();
       boolean hasKeytab = keytab != null && !keytab.trim().isEmpty();

       if (hasPrincipal && !hasKeytab) {
           errors.add(keytabKey + " is required when " + principalKey
                   + " is set");
       } else if (hasKeytab && !hasPrincipal) {
           errors.add(principalKey + " is required when " + keytabKey
                   + " is set");
       } else if (hasKeytab && !new File(keytab.trim()).canRead()) {
           errors.add("keytab file " + keytab + " is not readable");
       }
   }

   private static String resolveHostPattern(String principal) {
       if (principal == null) {
           return null;
       }
       try {
           String host = InetAddress.getLocalHost().getCanonicalHostName()
                   .toLowerCase(Locale.ROOT);
           return substituteHost(principal, host);
       } catch (UnknownHostException e) {
           return principal;
       }
   }

   /**
    * Replaces an instance of {@code _HOST} in {@code primary/instance[@REALM]}
    * with the host, as Hadoop does.
    */
   public static String substituteHost(String principal, String host) {
       int slash = principal.indexOf('/');
       if (slash < 0) {
           return principal;
       }
       int at = principal.indexOf('@', slash);
       String instance = at < 0 ? principal.substring(slash + 1)
               : principal.substring(slash + 1, at);
       if (!instance.equals(HOSTNAME_PATTERN)) {
           return principal;
       }
       return principal.substring(0, slash + 1) + host
               + (at < 0 ? "" : principal.substring(at));
   }
}
