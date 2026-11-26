ARG GO_IMAGE=golang:1.26-alpine
ARG DASHBOARDS_IMAGE=opensearchproject/opensearch-dashboards:3.10.0

FROM ${GO_IMAGE} AS proxy
WORKDIR /src
COPY access-proxy/go.mod access-proxy/go.sum ./
RUN go mod download
COPY access-proxy/ ./
RUN go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/access-proxy .

FROM ${DASHBOARDS_IMAGE}

# Authentication is enforced by Cloudflare Access + access-proxy.
RUN ./bin/opensearch-dashboards-plugin remove securityDashboards

COPY --chown=opensearch-dashboards:opensearch-dashboards config/opensearch_dashboards.yml /usr/share/opensearch-dashboards/config/opensearch_dashboards.yml
COPY --from=proxy /out/access-proxy /usr/local/bin/access-proxy
COPY bin/ /usr/local/bin/

ENV PORT=10000 \
    NODE_OPTIONS=--max-old-space-size=1280

EXPOSE 10000
ENTRYPOINT ["/usr/local/bin/soc-entrypoint.sh"]
