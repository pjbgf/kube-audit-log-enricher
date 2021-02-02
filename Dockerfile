FROM golang:1.15.7-alpine AS build
WORKDIR /work
RUN apk --no-cache add build-base git

# Speed up build by leveraging docker layer caching
COPY go.mod go.sum ./
RUN go mod download

ADD . /work
RUN make

FROM alpine
ARG version

LABEL name="Kube Audit Log Enricher" \
      version=$version \
      description="Enriches security logs with Kubernetes data."

COPY --from=build /work/bin/log-enricher /log-enricher

USER root

ENTRYPOINT ["/log-enricher"]
