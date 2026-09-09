FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/reliquary ./cmd/reliquary

FROM alpine:3.20
RUN adduser -D -u 10001 reliquary
COPY --from=build /out/reliquary /usr/local/bin/reliquary
USER reliquary
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/reliquary"]
CMD ["serve", "-listen", "0.0.0.0:8080"]
