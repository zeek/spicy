all: help

help:
	@echo
	@echo 'Run "make build-<platform>", then optionally "make test-<platform>",'
	@echo 'and finally "make run-<platform>".'
	@echo
	@echo Available platforms:
	@echo
	@ls Dockerfile.* | sed 's/Dockerfile\./    /' | sort

build-%:
	./docker-helper build $*

test-%:
	./docker-helper test $*

run-%:
	./docker-helper run $*

update_dockerhub: test-alpine-3.12 test-centos-8 test-ubuntu-18.04
	@: $${DOCKER_USERNAME:?"must be set to the username for login to Docker Hub"}
	@: $${DOCKER_PASSWORD_FILE:?"must be set to a file containing a password for login to Docker Hub"}
	@test -f "$$DOCKER_PASSWORD_FILE" || sh -c ">&2 echo 'File $$DOCKER_PASSWORD_FILE does not exist' && exit 1"
	cat "$$DOCKER_PASSWORD_FILE" | docker login --username="$$DOCKER_USERNAME" --password-stdin; \
	IMAGES="alpine-3.12 centos-8 ubuntu-18.04"; \
	VERSION=$$(../scripts/autogen-version --short); \
	for image in $${IMAGES}; do \
		for version in "$$VERSION" latest; do \
			IMAGE="spicy-$$image":"$$version"; \
			docker tag "$$IMAGE" "$$DOCKER_USERNAME/$$IMAGE"; \
			docker push "$$DOCKER_USERNAME/$$IMAGE"; \
		done \
	done; \
	docker logout
