FROM tomcat:9-jdk11-openjdk AS extract-container

ENV AM_WAR_NAME "am.war"

ADD forgerock-am/_binaries/amster.zip /
ADD forgerock-am/_binaries/${AM_WAR_NAME} /am.war
ADD forgerock-am/_binaries/openbanking-1-1-tpatch.zip /

RUN apt-get update && \
    apt-get install --no-install-recommends -y unzip && \
    mkdir -p /var/tmp/openam && \
    unzip -q /am.war -d /var/tmp/openam && \
    if ! grep -q "com.iplanet.am.buildVersion=ForgeRock Access Management 6.5.1" /var/tmp/openam/WEB-INF/classes/serverdefaults.properties; then \
    echo "ERROR: Provided war file is not AM version 6.5.1" && \
    echo "VERSION FOUND: $(grep 'com.iplanet.am.buildVersion=' /var/tmp/openam/WEB-INF/classes/serverdefaults.properties)" && \
    exit 10; \
    fi && \
    unzip /openbanking-1-1-tpatch.zip -d /var/tmp/openam && \
    mkdir -p /var/tmp/amster && \
    unzip -q /amster.zip -d /var/tmp/amster

FROM tomcat:9-jdk11-openjdk

SHELL ["/bin/bash", "-c"]
ENV AMSTER_KEY_PATH "/var/run/secrets/amster/id_rsa"
ENV FORGEROCK_HOME /home/forgerock
ENV OPENAM_HOME /home/forgerock/openam
ENV OB_DOMAIN dev-ob.forgerock.financial
ENV CATALINA_OPTS "-server -Xms2048m -Xmx2048m \
  -Dcom.sun.identity.util.debug.provider=com.sun.identity.shared.debug.impl.StdOutDebugProvider \
  -Dcom.sun.identity.shared.debug.file.format=\"%PREFIX% %MSG%\\n%STACKTRACE%\""


RUN rm -fr "$CATALINA_HOME"/webapps/*

COPY --from=extract-container /var/tmp/openam "$CATALINA_HOME"/webapps/ROOT
COPY --from=extract-container /var/tmp/amster /opt/amster

ADD https://github.com/krallin/tini/releases/download/v0.18.0/tini /usr/bin

RUN apt-get update && \
    apt-get install --no-install-recommends -y unzip curl bash procps openssh-client && \
    chmod +x /usr/bin/tini && \
    addgroup --gid 11111 forgerock && \
    adduser --shell /bin/bash --home "$FORGEROCK_HOME" --uid 11111 --disabled-password --ingroup root --gecos 'forgerock' forgerock && \
    mkdir -p "$OPENAM_HOME" && \
    mkdir -p "$OPENAM_HOME/secrets/plaintext" && \
    echo -n "changeit" > $OPENAM_HOME/secrets/plaintext/defaultpass && \
    chown -R forgerock:root "$CATALINA_HOME" && \
    chown -R forgerock:root  "$FORGEROCK_HOME" && \
    chmod -R g+rwx "$CATALINA_HOME"

ADD keystore/ca/*.crt /home/forgerock/
ADD keystore/obOfficialCertificates/*.cer /home/forgerock/
COPY forgerock-am/am/server.xml "$CATALINA_HOME"/conf/server.xml
COPY forgerock-am/am/web.xml "$CATALINA_HOME"/webapps/ROOT/WEB-INF/web.xml
ADD keystore/aspsp/keystore.jks /etc/ssl/certs/java/keystore.jks

RUN mkdir -p /var/run/secrets/amster && \
    ssh-keygen -t rsa -b 4096 -C "obri-amster@example.com" -f /var/run/secrets/amster/id_rsa -q -N "" && \
    if ! [ -f /etc/ssl/certs/java/cacerts ]; then ln -s $(find / -name cacerts | head -n1) /etc/ssl/certs/java/cacerts; fi && \
    keytool -import -alias obri-internal-ca -trustcacerts -noprompt \
            -keystore /etc/ssl/certs/java/cacerts -storepass changeit \
            -file /home/forgerock/obri-internal-ca.crt && \
    keytool -import -alias obri-external-ca -trustcacerts -noprompt \
            -keystore /etc/ssl/certs/java/cacerts -storepass changeit \
            -file /home/forgerock/obri-external-ca.crt && \ 
    keytool -import -alias obsandboxrootca -trustcacerts -noprompt \
            -keystore /etc/ssl/certs/java/cacerts -storepass changeit \
            -file /home/forgerock/OB_SandBox_PP_Root_CA.cer && \ 
    keytool -import -alias obsandboxissuingca -trustcacerts -noprompt \
            -keystore /etc/ssl/certs/java/cacerts -storepass changeit \
            -file /home/forgerock/OB_SandBox_PP_Issuing_CA.cer
    

ADD forgerock-am/amster/ /opt/amster/
ADD forgerock-am/am/*.sh $FORGEROCK_HOME/

RUN echo "127.0.0.1  openam" >> /etc/hosts && \
    /usr/local/tomcat/bin/catalina.sh start && \
    tail -f /usr/local/tomcat/logs/catalina.out | while read LOGLINE; do \
        echo "${LOGLINE}"; \
        [[ "${LOGLINE}" == *"Server startup in"* ]] && pkill -P $$ tail; \
    done && \
    cd /opt/amster && \
    set -euo pipefail && \
    /opt/amster/amster-install.sh |& tee /amster.log && \
    if grep -q "IMPORT ERRORS\|SCRIPT ERROR\|Exception\|\(F\|f\)ailed\|\(U\|u\)nexpected" /amster.log; then echo "ABORTING BUILD DUE TO AMSTER ERRORS." && exit 10; fi && \
    if ! grep -q "Import completed successfully" /amster.log; then echo "ABORTING BECAUSE AMSTER IMPORT DID NOT COMPLETE." && exit 10; fi && \
    echo "Shutting down tomcat" && \
    /usr/local/tomcat/bin/catalina.sh stop && \
    sleep 10

ENTRYPOINT ["/home/forgerock/docker-entrypoint.sh"]
CMD ["run"]