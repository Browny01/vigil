FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
COPY web ./web
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /vigil . && mkdir /data && chown 65532:65532 /data
FROM scratch
COPY --from=build /vigil /vigil
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
EXPOSE 9120
ENTRYPOINT ["/vigil"]
CMD ["-listen=0.0.0.0:9120", "-state=/data", "-proc-root=/host/proc", "-host-root=/host"]
