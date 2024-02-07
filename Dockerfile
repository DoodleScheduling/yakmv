FROM gcr.io/distroless/static:latest
WORKDIR /
COPY yakmv yakmv

ENTRYPOINT ["/yakmv"]
