all: help

help:
	@echo
	@echo 'Run "make build-<platform>", then optionally "make test-<platform>",'
	@echo 'and finally "make run-<platform>".'
	@echo
	@echo Available platforms:
	@echo
	@cat Makefile | awk -F '[-:]' '/^build-/ { printf("    %s-%s\n", $$2, $$3); }' | sort
	@echo

build-ubuntu-19.10:
	./docker-helper build ubuntu-19.10

test-ubuntu-19.10: build-ubuntu-19.10
	./docker-helper test ubuntu-19.10

run-ubuntu-19.10:
	./docker-helper run ubuntu-19.10

build-alpine-3.11:
	./docker-helper build alpine-3.11

test-alpine-3.11: build-alpine-3.11
	./docker-helper test alpine-3.11

run-alpine-3.11:
	./docker-helper run alpine-3.11

build-centos-8:
	./docker-helper build centos-8

test-centos-8: build-centos-8
	./docker-helper test centos-8

run-centos-8:
	./docker-helper run centos-8

update_dockerhub: test-alpine-3.11 test-centos-8 test-ubuntu-19.10
	@: $${DOCKER_USERNAME:?"must be set to the username for login to Docker Hub"}
	@: $${DOCKER_PASSWORD_FILE:?"must be set to a file containing a password for login to Docker Hub"}
	@test -f "$$DOCKER_PASSWORD_FILE" || sh -c ">&2 echo 'File $$DOCKER_PASSWORD_FILE does not exist' && exit 1"
	cat "$$DOCKER_PASSWORD_FILE" | docker login --username="$$DOCKER_USERNAME" --password-stdin; \
	IMAGES="alpine-3.11 centos-8 ubuntu-19.10"; \
	VERSION=$$(../scripts/autogen-version --short); \
	for image in $${IMAGES}; do \
		for version in "$$VERSION" latest; do \
			IMAGE="spicy-$$image":"$$version"; \
			docker tag "$$IMAGE" "$$DOCKER_USERNAME/$$IMAGE"; \
			docker push "$$DOCKER_USERNAME/$$IMAGE"; \
		done \
	done; \
	docker logout
