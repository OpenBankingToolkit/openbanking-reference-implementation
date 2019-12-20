FROM debian:stable-slim

ADD forgerock-am/_binaries/amster.zip /
ADD forgerock-am/_binaries/am.war /

RUN apt-get update && \
    apt-get install --no-install-recommends -y unzip && \
    mkdir -p /var/tmp/openam && \
    unzip -q /am.war -d /var/tmp/openam && \
    mkdir -p /var/tmp/amster && \
    unzip -q /amster.zip -d /var/tmp/amster

FROM tomcat:9-jre11-slim

SHELL ["/bin/bash", "-c"]
ENV FORGEROCK_HOME /home/forgerock
ENV OPENAM_HOME /home/forgerock/openam
ENV OB_DOMAIN dev-ob.forgerock.financial
ENV CATALINA_OPTS "-Xms2048m -Xmx2048m"

RUN rm -fr "$CATALINA_HOME"/webapps/*
COPY --from=0 /var/tmp/openam "$CATALINA_HOME"/webapps/ROOT
COPY --from=0 /var/tmp/amster /opt/amster

ADD https://github.com/krallin/tini/releases/download/v0.18.0/tini /usr/bin

RUN apt-get update && \
    apt-get install --no-install-recommends -y unzip curl bash procps openssh-client && \
    chmod +x /usr/bin/tini && \
    addgroup --gid 11111 forgerock && \
    adduser --shell /bin/bash --home "$FORGEROCK_HOME" --uid 11111 --disabled-password --ingroup root --gecos 'forgerock' forgerock && \
    mkdir -p "$OPENAM_HOME" && \
    chown -R forgerock:root "$CATALINA_HOME" && \
    chown -R forgerock:root  "$FORGEROCK_HOME" && \
    chmod -R g+rwx "$CATALINA_HOME"

ADD keystore/ca/*.crt /home/forgerock/
COPY  forgerock-am/am/server.xml "$CATALINA_HOME"/conf/server.xml
ADD keystore/common/keystore.jks /etc/ssl/certs/java/keystore.jks

RUN mkdir -p /var/run/secrets/amster && \
    ssh-keygen -t rsa -b 4096 -C "obri-amster@example.com" -f /var/run/secrets/amster/id_rsa -q -N "" && \
    keytool -import -alias obri-internal-ca -trustcacerts -noprompt \
            -keystore /etc/ssl/certs/java/cacerts -storepass changeit \
            -file /home/forgerock/obri-internal-ca.crt && \
    keytool -import -alias obri-external-ca -trustcacerts -noprompt \
            -keystore /etc/ssl/certs/java/cacerts -storepass changeit \
            -file /home/forgerock/obri-external-ca.crt

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
    if grep -q "Failed to\|IMPORT ERRORS\|SCRIPT ERROR\|Exception\|Configuration failed" /amster.log; then echo "ABORTING BUILD DUE TO AMSTER ERRORS." && exit 10; fi && \
    echo "Shutting down tomcat" && \
    /usr/local/tomcat/bin/catalina.sh stop && \
    sleep 10

ENTRYPOINT ["/home/forgerock/docker-entrypoint.sh"]
CMD ["run"]