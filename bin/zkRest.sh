#!/bin/bash

# Starts ZooKeeper REST contrib (org.apache.zookeeper.server.jersey.RestMain)

set -euo pipefail

ZK_HOME="${ZK_HOME:-/usr/lib/zookeeper}"

ZK_CONF="${ZK_CONF:-/etc/zookeeper/conf}"

ZK_REST_JVMFLAGS="${ZK_REST_JVMFLAGS:-}"

set +u

if [ -r "${ZK_CONF}/zookeeper-env.sh" ]; then

  # shellcheck disable=SC1090,SC1091
  . "${ZK_CONF}/zookeeper-env.sh"

else

  export ADH_SERVICE_NAME=ZOOKEEPER

  # shellcheck disable=SC1091
  . /usr/lib/bigtop-utils/bigtop-detect-javahome

fi

set -u

if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then

  JAVA="${JAVA_HOME}/bin/java"

elif command -v java >/dev/null 2>&1; then

  JAVA=java

else

  echo "No java found: set JAVA_HOME or put java on PATH" >&2

  exit 1

fi

# jersey-json's JAXB injects accessor bytecode, which the module system of
# Java 9+ refuses unless java.lang is open to the unnamed module

JAVA_MAJOR=$("$JAVA" -version 2>&1 | awk -F'"' '/version/ {split($2, v, "."); if (v[1] == "1") print v[2]; else print v[1]}')

if [ "$JAVA_MAJOR" -ge 9 ] 2>/dev/null; then

  ZK_REST_JVMFLAGS="--add-opens java.base/java.lang=ALL-UNNAMED ${ZK_REST_JVMFLAGS}"

fi

ZKREST_CONF="${ZKREST_CONF:-${ZK_CONF}/rest/rest.properties}"

if [ ! -r "${ZKREST_CONF}" ]; then

  echo "Config file is not readable: ${ZKREST_CONF}" >&2

  exit 1

fi

CLASSPATH="${ZK_HOME}/contrib/rest/*"

CLASSPATH="${CLASSPATH}:${ZK_HOME}/contrib/rest/lib/*"

CLASSPATH="${CLASSPATH}:${ZK_HOME}/*"

CLASSPATH="${CLASSPATH}:${ZK_HOME}/lib/*"

# shellcheck disable=SC2086

exec "$JAVA" ${ZK_REST_JVMFLAGS} -cp "${CLASSPATH}" \
    org.apache.zookeeper.server.jersey.RestMain "${ZKREST_CONF}"
