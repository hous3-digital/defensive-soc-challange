ARG CRS_IMAGE=owasp/modsecurity-crs:4.30.0-nginx-202611190211
ARG VECTOR_IMAGE=timberio/vector:0.62.0-distroless-static

FROM ${VECTOR_IMAGE} AS vector

FROM ${CRS_IMAGE}

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends supervisor \
 && rm -rf /var/lib/apt/lists/* \
 && install -d -o nginx -g nginx /var/log/edge /var/lib/vector

COPY --from=vector /usr/local/bin/vector /usr/local/bin/vector
COPY supervisord.conf /etc/supervisor/supervisord.conf
COPY bin/ /usr/local/bin/
COPY nginx/entrypoint.d/ /docker-entrypoint.d/
COPY --chown=nginx:nginx nginx/templates/ /etc/nginx/templates/
COPY vector/vector.yaml /etc/vector/vector.yaml

# ModSecurity/CRS knobs consumed by the base image entrypoint scripts.
ENV MODSEC_RULE_ENGINE=DetectionOnly \
    MODSEC_AUDIT_ENGINE=RelevantOnly \
    MODSEC_AUDIT_LOG=/dev/stdout \
    MODSEC_AUDIT_LOG_FORMAT=JSON \
    MODSEC_AUDIT_LOG_TYPE=Serial \
    MODSEC_AUDIT_LOG_PARTS=ABIFHZ \
    BLOCKING_PARANOIA=1 \
    DETECTION_PARANOIA=2 \
    SET_REAL_IP_FROM=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1 \
    CLIENT_MAX_BODY_SIZE=10m \
    PROXY_TIMEOUT=60s \
    PORT=8080 \
    VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1
USER nginx
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
