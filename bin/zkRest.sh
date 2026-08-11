#!/bin/bash

# Starts ZooKeeper REST contrib (org.apache.zookeeper.server.jersey.RestMain)

set -euo pipefail

ZK_HOME="${ZK_HOME:-/usr/lib/zookeeper}"

ZK_CONF="${ZK_CONF:-/etc/zookeeper/conf}"

ZK_REST_JVMFLAGS="${ZK_REST_JVMFLAGS:-}"

ZK_REST_JAVA_HOME="${ZK_REST_JAVA_HOME:-/usr/lib/jvm/java-arenadata-openjdk-11}"

if [ -x "${ZK_REST_JAVA_HOME}/bin/java" ]; then

JAVA_HOME="${ZK_REST_JAVA_HOME}"

else

set +u

if [ -r "${ZK_CONF}/zookeeper-env.sh" ]; then

# shellcheck disable=SC1090

. "${ZK_CONF}/zookeeper-env.sh"

else

export ADH_SERVICE_NAME=ZOOKEEPER

# shellcheck disable=SC1091

. /usr/lib/bigtop-utils/bigtop-detect-javahome

fi

set -u

fi

if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME}/bin/java" ]; then

echo "JAVA_HOME is not set or java is not executable: ${JAVA_HOME:-}" >&2

exit 1

fi

if [ -f "${ZK_CONF}/zk-rest-jaas.conf" ]; then

ZK_REST_JVMFLAGS="${ZK_REST_JVMFLAGS} -Djava.security.auth.login.config=${ZK_CONF}/zk-rest-jaas.conf"

ZK_REST_JVMFLAGS="${ZK_REST_JVMFLAGS} -Dzookeeper.sasl.client=true"

ZK_REST_JVMFLAGS="${ZK_REST_JVMFLAGS} -Dzookeeper.sasl.clientconfig=Client"

fi

CLASSPATH="${ZK_CONF}/rest"

CLASSPATH="${CLASSPATH}:${ZK_HOME}/contrib/rest/*"

CLASSPATH="${CLASSPATH}:${ZK_HOME}/contrib/rest/lib/*"

CLASSPATH="${CLASSPATH}:${ZK_HOME}/*"

CLASSPATH="${CLASSPATH}:${ZK_HOME}/lib/*"

# shellcheck disable=SC2086

exec "${JAVA_HOME}/bin/java" ${ZK_REST_JVMFLAGS} -cp "${CLASSPATH}" org.apache.zookeeper.server.jersey.RestMain

