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

test-%: build-%
	./docker-helper test $*

run-%:
	./docker-helper run $*

update_dockerhub: test-ubuntu-18
	@: $${DOCKER_USERNAME:?"must be set to the username for login to Docker Hub"}
	@: $${DOCKER_PASSWORD_FILE:?"must be set to a file containing a password for login to Docker Hub"}
	@test -f "$$DOCKER_PASSWORD_FILE" || sh -c ">&2 echo 'File $$DOCKER_PASSWORD_FILE does not exist' && exit 1"
	cat "$$DOCKER_PASSWORD_FILE" | docker login --username="$$DOCKER_USERNAME" --password-stdin; \
	VERSION=$$(../scripts/autogen-version --short); \
	for version in "$$VERSION" latest; do \
		echo docker tag "spicy:$$VERSION-ubuntu-18" "$$DOCKER_USERNAME/spicy:$$VERSION"; \
		echo docker push "$$DOCKER_USERNAME/spicy"; \
	done \
	docker logout
