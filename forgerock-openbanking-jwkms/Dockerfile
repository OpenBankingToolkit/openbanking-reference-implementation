FROM r.cfcr.io/openbanking/obri/basems

ARG JAR_FILE
ARG VERSION_FILE
ARG SERVICE_FILE

COPY ${JAR_FILE} ${VERSION_FILE} ${SERVICE_FILE} /opt/ob/


WORKDIR /opt/ob
RUN chown -R ob:ob /opt/ob
USER ob
CMD ["/opt/ob/sbootwait.sh"]
