test:
	sh tests/run.sh

lint:
	shellcheck -x */check.sh */stage2.sh */test*.sh tests/*.sh templates/check/*.sh

check: lint test

.PHONY: test lint check
