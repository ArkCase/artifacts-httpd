ARG BUILDER_IMAGE="golang"
ARG BUILDER_VER="1.23-alpine3.21"
ARG ARCH="amd64"
ARG OS="linux"
ARG VER="1.0.0"

FROM "${BUILDER_IMAGE}:${BUILDER_VER}" AS builder

ARG SRCPATH="/build/artifacts-httpd"

RUN apk --no-cache add git && \
    mkdir -p "${SRCPATH}"

ADD . "${SRCPATH}"

RUN cd "${SRCPATH}" && \
    GO111MODULE=on \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -a -ldflags '-extldflags "-static"' -o /artifacts-httpd

FROM scratch

ARG VER

LABEL ORG="ArkCase LLC" \
      MAINTAINER="Armedia Devops Team <devops@armedia.com>" \
      APP="ArkCase Artifacts HTTPD Server for Kubernetes" \
      VERSION="${VER}"

COPY --from=builder /artifacts-httpd /artifacts-httpd

ENTRYPOINT [ "/artifacts-httpd" ]
