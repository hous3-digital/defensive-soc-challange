ARG OPENSEARCH_IMAGE=opensearchproject/opensearch:3.10.1
ARG GOSU_IMAGE=tianon/gosu:1.20

FROM ${GOSU_IMAGE} AS gosu

FROM ${OPENSEARCH_IMAGE}

# The performance analyzer agent opens an extra listener (9600) we do not use.
RUN ./bin/opensearch-plugin remove opensearch-performance-analyzer

COPY --chown=opensearch:opensearch config/opensearch.yml /usr/share/opensearch/config/opensearch.yml
COPY bootstrap/ /usr/share/opensearch/soc-bootstrap/
COPY bin/ /usr/local/bin/
COPY --from=gosu /usr/local/bin/gosu /usr/local/bin/gosu

ENV DISABLE_SECURITY_PLUGIN=true \
    DISABLE_INSTALL_DEMO_CONFIG=true \
    DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true \
    OPENSEARCH_JAVA_OPTS="-Xms2g -Xmx2g" \
    SOC_DATA_ROOT=/var/lib/opensearch \
    SOC_RETENTION_DAYS=14

# Starts as root only to fix ownership of the mounted disk, then drops to
# the opensearch user via gosu.
USER root
EXPOSE 9200
ENTRYPOINT ["/usr/local/bin/soc-entrypoint.sh"]
CMD ["opensearch"]
