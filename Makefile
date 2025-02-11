#
IMAGE?=public.ecr.aws/arkcase/artifacts-httpd

TAG_GIT=$(IMAGE):1.0.0
TAG_LATEST=$(IMAGE):latest

PHONY: test-image
test-image: image
	docker build -t artifacts-httpd -f Dockerfile .

PHONY: all
all: image

PHONY: artifacts-httpd
artifacts-httpd: export CGO_ENABLED=0
artifacts-httpd: export GO111MODULE=on
artifacts-httpd: $(shell find . -name "*.go")
	go build -a -ldflags '-extldflags "-static"' -o artifacts-httpd .

PHONY: image
image: artifacts-httpd
	docker build -t $(TAG_GIT) -f Dockerfile .
	docker tag $(TAG_GIT) $(TAG_LATEST)
