FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X ariadns/internal/version.Version=${VERSION}" -o /ariadns ./cmd/ariadns

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /ariadns /ariadns
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp
ENTRYPOINT ["/ariadns"]
CMD ["-config", "/etc/ariadns/config.json"]
