ARG VECTOR_IMAGE=timberio/vector:0.62.0-distroless-static
ARG BUSYBOX_IMAGE=busybox:1.37

FROM ${BUSYBOX_IMAGE} AS dirs
RUN mkdir -p /out/var/lib/vector

FROM ${VECTOR_IMAGE}
COPY --from=dirs --chown=65532:65532 /out/var/lib/ /var/lib/
COPY vector/vector.yaml /etc/vector/vector.yaml
# Vector >= 0.62 only expands ${VAR} in config files when explicitly allowed.
ENV PORT=8080 \
    VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true
EXPOSE 8080
USER 65532:65532
CMD ["--config", "/etc/vector/vector.yaml"]
