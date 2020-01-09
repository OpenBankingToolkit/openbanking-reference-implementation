FROM gcr.io/forgerock-io/am@sha256:0443c576fa8ad6900e05471d14c8d33768f7f3bf7b4eb3e22265696dfb4dfa6b AS am-pit-container
FROM gcr.io/forgerock-io/amster@sha256:8a91d06d08637e1bad318da506673aeb296c948433f12c56aa0a03da8a75f47e AS amster-pit-container

# FROM tomcat:9-jdk11-openjdk AS extract-container

# ENV AM_WAR_NAME "am-sam.war"

# ADD forgerock-am/_binaries/amster.zip /
# ADD forgerock-am/_binaries/${AM_WAR_NAME} /am.war
# # ADD forgerock-am/_binaries/openbanking-1-1-tpatch.zip /

# RUN apt-get update && \
#     apt-get install --no-install-recommends -y unzip && \
#     mkdir -p /var/tmp/openam && \
#     unzip -q /am.war -d /var/tmp/openam && \
#     # unzip /openbanking-1-1-tpatch.zip -d /var/tmp/openam && \
#     mkdir -p /var/tmp/amster && \
#     unzip -q /amster.zip -d /var/tmp/amster

FROM tomcat:9-jdk11-openjdk

SHELL ["/bin/bash", "-c"]
ENV AMSTER_KEY_PATH "/home/forgerock/openam/security/keys/amster"
ENV FORGEROCK_HOME /home/forgerock
ENV OPENAM_HOME /home/forgerock/openam
ENV OB_DOMAIN dev-ob.forgerock.financial
ENV CATALINA_OPTS "-server -Xms2048m -Xmx2048m \
  -Dcom.sun.identity.util.debug.provider=com.sun.identity.shared.debug.impl.StdOutDebugProvider \
  -Dcom.sun.identity.shared.debug.file.format=\"%PREFIX% %MSG%\\n%STACKTRACE%\" \
  -Dcom.iplanet.services.stats.state=off"


RUN rm -fr "$CATALINA_HOME"/webapps/*

# COPY --from=extract-container /var/tmp/openam "$CATALINA_HOME"/webapps/ROOT
# COPY --from=extract-container /var/tmp/amster /opt/amster

COPY --from=am-pit-container /usr/local/tomcat/webapps/am "$CATALINA_HOME"/webapps/ROOT
COPY --from=amster-pit-container /opt/amster /opt/amster

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
COPY  forgerock-am/am/server.xml "$CATALINA_HOME"/conf/server.xml
ADD keystore/aspsp/keystore.jks /etc/ssl/certs/java/keystore.jks

RUN mkdir -p /var/run/secrets/amster && \
    ssh-keygen -t rsa -b 4096 -C "obri-amster@example.com" -f /var/run/secrets/amster/id_rsa -q -N "" && \
    if ! [ -f /etc/ssl/certs/java/cacerts ]; then ln -s $(find / -name cacerts | head -n1) /etc/ssl/certs/java/cacerts; fi && \
    keytool -import -alias obri-internal-ca -trustcacerts -noprompt \
            -keystore /usr/local/openjdk-11/lib/security/cacerts -storepass changeit \
            -file /home/forgerock/obri-internal-ca.crt && \
    keytool -import -alias obri-external-ca -trustcacerts -noprompt \
            -keystore /usr/local/openjdk-11/lib/security/cacerts -storepass changeit \
            -file /home/forgerock/obri-external-ca.crt && \ 
    keytool -import -alias obsandboxrootca -trustcacerts -noprompt \
            -keystore /usr/local/openjdk-11/lib/security/cacerts -storepass changeit \
            -file /home/forgerock/OB_SandBox_PP_Root_CA.cer && \ 
    keytool -import -alias obsandboxissuingca -trustcacerts -noprompt \
            -keystore /usr/local/openjdk-11/lib/security/cacerts -storepass changeit \
            -file /home/forgerock/OB_SandBox_PP_Issuing_CA.cer
    

ADD forgerock-am/amster/ /opt/amster/
ADD forgerock-am/am/*.sh $FORGEROCK_HOME/
# COPY forgerock-am/am/logback.xml /usr/local/tomcat/webapps/am/WEB-INF/classes

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
    echo "Shutting down tomcat" && \
    /usr/local/tomcat/bin/catalina.sh stop && \
    sleep 10

ENTRYPOINT ["/home/forgerock/docker-entrypoint.sh"]
CMD ["run"]