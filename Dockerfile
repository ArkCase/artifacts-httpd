ARG VER="1.1.0"
ARG GO="1.24"
ARG ARCH="amd64"
ARG OS="linux"

ARG BUILDER_IMAGE="golang"
ARG BUILDER_VER="${GO}-alpine"
ARG BUILDER_IMG="${BUILDER_IMAGE}:${BUILDER_VER}"

FROM "${BUILDER_IMG}" AS builder

ARG SRCPATH="/build/artifacts-httpd"

ARG VER
ARG GO
ARG ARCH
ARG OS

RUN apk --no-cache add git && \
    mkdir -p "${SRCPATH}"

ADD . "${SRCPATH}"

ENV GO111MODULE="on"
ENV CGO_ENABLED="0"
ENV GOOS="${OS}"
ENV GOARCH="${ARCH}"
RUN cd "${SRCPATH}" && \
    go mod edit -go "${GO}" && \
    go get -u && \
    go mod tidy && \
    go build -a -ldflags "-X 'main.AppVersion=v${VER}' -extldflags '-static'" -o /artifacts-httpd

FROM scratch

ARG VER

LABEL ORG="ArkCase LLC" \
      MAINTAINER="Armedia Devops Team <devops@armedia.com>" \
      APP="ArkCase Artifacts HTTPD Server for Kubernetes" \
      VERSION="${VER}"

COPY --from=builder /artifacts-httpd /artifacts-httpd

ENTRYPOINT [ "/artifacts-httpd" ]
