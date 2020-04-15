FROM eu.gcr.io/openbanking-214714/obri/basems

ARG JAR_FILE
ARG VERSION_FILE
ARG SERVICE_FILE

COPY ${JAR_FILE} ${VERSION_FILE} ${SERVICE_FILE} /opt/ob/

WORKDIR /opt/ob
RUN chown -R ob:ob /opt/ob

#Keystore workaround...
RUN mkdir -p /opt/openbanking && \
    ln -s /opt/ob /opt/openbanking/$SVC

USER ob
CMD ["/opt/ob/sbootwait.sh"]