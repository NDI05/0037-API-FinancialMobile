# syntax=docker/dockerfile:1
# Image runtime untuk host gratis (Render/Docker VM). Build statis, tanpa CGO.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/pam-api ./cmd/api

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /app --create-home app \
 && mkdir -p /data && chown app:app /data
COPY --from=build /out/pam-api /app/pam-api
WORKDIR /app
USER app
EXPOSE 8080
ENTRYPOINT ["/app/pam-api"]
