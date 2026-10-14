FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS backend
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
ARG GO_MODULE_PROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GO_MODULE_PROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" -o /out/web-console ./cmd/web-console \
    && mkdir -p /out/data && chmod 700 /out/data

FROM scratch AS runtime
ARG VERSION=dev
LABEL org.opencontainers.image.title="web-console" \
      org.opencontainers.image.description="Lightweight web device console with OIDC authentication" \
      org.opencontainers.image.source="https://github.com/Keviince/web-console" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version=$VERSION
COPY --from=backend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=backend /out/web-console /usr/local/bin/web-console
COPY --from=backend --chown=10001:10001 /out/data /app/data
COPY --from=frontend /src/web/dist /app/web/dist
WORKDIR /app
USER 10001:10001
EXPOSE 8080
ENV LISTEN=:8080 DATA_DIR=/app/data WEB_ROOT=/app/web/dist
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/web-console", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/web-console"]
