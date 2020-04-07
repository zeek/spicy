
IMAGE=rsmmr/spicy-ci-ubuntu

all:

docker-build:
	(cd .. && docker build -t $(IMAGE) -f ci/Dockerfile .)

docker-build-no-cache:
	(cd .. && docker build -t $(IMAGE) -f ci/Dockerfile .)

docker-run:
	docker run --cap-add SYS_PTRACE -i -t $(IMAGE) /bin/bash

docker-push:
	docker tag ${IMAGE} $(IMAGE):latest
	docker push $(IMAGE):latest
