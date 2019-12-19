FROM debian:stable-slim

ADD _binaries/amster.zip /
ADD _binaries/am.war /

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

RUN rm -fr "$CATALINA_HOME"/webapps/*
COPY --from=0 /var/tmp/openam "$CATALINA_HOME"/webapps/ROOT
COPY --from=0 /var/tmp/amster /opt/amster

ADD https://github.com/krallin/tini/releases/download/v0.18.0/tini /usr/bin

RUN apt-get update && \
    apt-get install --no-install-recommends -y unzip curl bash procps && \
    chmod +x /usr/bin/tini && \
    addgroup --gid 11111 forgerock && \
    adduser --shell /bin/bash --home "$FORGEROCK_HOME" --uid 11111 --disabled-password --ingroup root --gecos 'forgerock' forgerock && \
    mkdir -p "$OPENAM_HOME" && \
    chown -R forgerock:root "$CATALINA_HOME" && \
    chown -R forgerock:root  "$FORGEROCK_HOME" && \
    chmod -R g+rwx "$CATALINA_HOME"

RUN export CATALINA_OPTS="-Xmx1024m -Xms1024m " && \
    export OB_DOMAIN="dev-ob.forgerock.financial" && \
    /usr/local/tomcat/bin/catalina.sh start && \
    tail -f /usr/local/tomcat/logs/catalina.out | while read LOGLINE; do \
        echo "${LOGLINE}"; \
        [[ "${LOGLINE}" == *"Server startup in"* ]] && pkill -P $$ tail; \
    done && \
    cd /opt/amster && \
    /opt/amster/amster-install.sh | tee /amster.log && \
    if grep "Failed to import\|IMPORT ERRORS\|SCRIPT ERROR" /amster.log; then echo "ABORTING BUILD DUE TO ERRORS." && exit 10; fi && \
    /usr/local/tomcat/bin/catalina.sh stop && \
    sleep 10

#TODO: add amster scripts, amster-install.sh
#TODO: simple amster config
#TODO: Do we need to create the OUs in the embedded DS for the different realms?
#TODO: entrypoint script
#TODO: Does AM need to run on SSL?