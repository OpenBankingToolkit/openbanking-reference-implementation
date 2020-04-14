FROM eu.gcr.io/openbanking-214714/obri/basems

ARG JAR_FILE
ARG VERSION_FILE
ARG SERVICE_FILE

COPY ${JAR_FILE} ${VERSION_FILE} ${SERVICE_FILE} /opt/ob/

RUN rm -rf /var/lib/apt/lists/*  && \
    apt-get update -y && \
    apt-get install git openssh-client -y && \
    mkdir -p /opt/ob/.ssh && \
    ssh-keyscan -t rsa -p 7999 stash.forgerock.org > /opt/ob/.ssh/known_hosts && \
    chown -R ob:ob /opt/ob && \
    chmod 700 /opt/ob/.ssh && \
    chmod 600 /opt/ob/.ssh/*

WORKDIR /opt/ob
USER ob

ADD forgerock-openbanking-git-config /opt/ob/forgerock-openbanking-config/forgerock-openbanking-git-config

CMD ["sh", "-c", "java -jar /opt/ob/forgerock-openbanking-config-*.jar"]