#!/usr/bin/env bash
set -e

cd /codefresh/volume/ob-reference-implementation

echo "Installing certs"
keytool -import -trustcacerts -noprompt -alias frobca-internal -file keystore/ca/obri-internal-ca.cer     -keystore ${JAVA_HOME}/lib/security/cacerts -storepass changeit
keytool -import -trustcacerts -noprompt -alias frobca-external -file keystore/ca/obri-external-ca.cer     -keystore ${JAVA_HOME}/lib/security/cacerts -storepass changeit
keytool -import -trustcacerts -noprompt -alias obtestrootca -file keystore/obOfficialCertificates/obtestrootca.cer     -keystore ${JAVA_HOME}/lib/security/cacerts -storepass changeit
keytool -import -trustcacerts -noprompt -alias obtestissuerca -file keystore/obOfficialCertificates/obtestissuingca.cer     -keystore ${JAVA_HOME}/lib/security/cacerts -storepass changeit

mvn -Dspring.cloud.config.uri=http://config.dev-ob.forgerock.financial:8888 \
 -Dmaven.repo.local=/codefresh/volume/$1/.m2/repository \
 -Dspring.data.mongodb.uri=mongodb://mongo:27017/test \
 -Ddockerfile.skip \
 -DdockerCompose.skip \
 verify \
 -f $2