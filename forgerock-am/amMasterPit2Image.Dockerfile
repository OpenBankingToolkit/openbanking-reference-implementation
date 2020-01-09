FROM gcr.io/forgerock-io/amster/pit1:latest AS amster-pit-container
FROM gcr.io/forgerock-io/am/pit1:latest
USER root
SHELL ["/bin/bash", "-c"]
ENV OB_DOMAIN dev-ob.forgerock.financial
ENV CATALINA_OPTS "-server -Xms2048m -Xmx2048m \
                   -Dcom.sun.services.debug.mergeall=on \
                   -Dcom.sun.identity.configuration.directory=/home/forgerock/openam \
                   -Dcom.iplanet.services.stats.state=off"

COPY --from=amster-pit-container /opt/amster /opt/amster

RUN mv /usr/local/tomcat/webapps/am /usr/local/tomcat/webapps/ROOT && \
    apt-get update && \
    apt-get install --no-install-recommends -y unzip curl bash procps openssh-client && \
    mkdir -p "$AM_HOME" && \
    mkdir -p "$AM_HOME/secrets/plaintext" && \
    echo -n "changeit" > $AM_HOME/secrets/plaintext/defaultpass

ADD keystore/ca/*.crt /home/forgerock/
ADD keystore/obOfficialCertificates/*.cer /home/forgerock/
COPY  forgerock-am/am/server.xml "$CATALINA_HOME"/conf/server.xml
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

USER forgerock
ENTRYPOINT [ "/usr/local/tomcat/bin/catalina.sh", "run" ]