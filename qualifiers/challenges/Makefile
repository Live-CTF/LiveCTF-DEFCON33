.PHONY: challenges
# Update here
challenges: challenge-test-challenge \
	challenge-sokobin \
	challenge-unwind-me-maybe \
	challenge-no-f-in-the-stack \
	challenge-ropably \
	challenge-multi-level-model-marketing \
	challenge-n-buns

###############################################################################
# test-challenge

.PHONY: challenge-test-challenge
challenge-test-challenge: handouts/quals-test-challenge-handout.tar.gz

handouts/quals-test-challenge-handout.tar.gz: $(shell find test-challenge/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-test-challenge test-challenge/challenge
	./extract-handout.sh quals-test-challenge

.PHONY: run-test-challenge
run-test-challenge: challenge-test-challenge
	./test-run.sh quals-test-challenge

.PHONY: solution-test-challenge
solution-test-challenge: challenge-test-challenge $(shell find test-challenge/solution -type f)
	cp handouts/quals-test-challenge-handout.tar.gz test-challenge/solution/handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-test-challenge_exploit test-challenge/solution
	./test-solution.sh quals-test-challenge

push-test-challenge-remote: handouts/quals-test-challenge-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-test-challenge test-challenge/challenge
	docker tag livectf:quals-test-challenge localhost:6000/b4f31f6edb2fdec8-test-challenge:latest
	docker push localhost:6000/b4f31f6edb2fdec8-test-challenge:latest
	gcloud storage cp handouts/quals-test-challenge-handout.tar.gz 'gs://livectf25-challenges/test-challenge.tgz'

push-test-challenge-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-test-challenge test-challenge/challenge
	docker tag livectf:quals-test-challenge localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# sokobin

.PHONY: challenge-sokobin
challenge-sokobin: handouts/quals-sokobin-handout.tar.gz

handouts/quals-sokobin-handout.tar.gz: $(shell find sokobin/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-sokobin sokobin/challenge
	./extract-handout.sh quals-sokobin

.PHONY: run-sokobin
run-sokobin: challenge-sokobin
	./test-run.sh quals-sokobin

.PHONY: solution-sokobin
solution-sokobin: challenge-sokobin $(shell find sokobin/solution -type f)
	cp handouts/quals-sokobin-handout.tar.gz sokobin/solution/handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-sokobin_exploit sokobin/solution
	./test-solution.sh quals-sokobin

push-sokobin-remote: handouts/quals-sokobin-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-sokobin sokobin/challenge
	docker tag livectf:quals-sokobin localhost:6000/b4f31f6edb2fdec8-sokobin:latest
	docker push localhost:6000/b4f31f6edb2fdec8-sokobin:latest
	gcloud storage cp handouts/quals-sokobin-handout.tar.gz 'gs://livectf25-challenges/sokobin.tgz'

push-sokobin-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-sokobin sokobin/challenge
	docker tag livectf:quals-sokobin localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# no-f-in-the-stack

.PHONY: challenge-no-f-in-the-stack
challenge-no-f-in-the-stack: handouts/quals-no-f-in-the-stack-handout.tar.gz

handouts/quals-no-f-in-the-stack-handout.tar.gz: $(shell find no-f-in-the-stack/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-no-f-in-the-stack no-f-in-the-stack/challenge
	./extract-handout.sh quals-no-f-in-the-stack

.PHONY: run-no-f-in-the-stack
run-no-f-in-the-stack: challenge-no-f-in-the-stack
	./test-run.sh quals-no-f-in-the-stack

.PHONY: solution-no-f-in-the-stack
solution-no-f-in-the-stack: challenge-no-f-in-the-stack $(shell find no-f-in-the-stack/solution -type f)
	cp handouts/quals-no-f-in-the-stack-handout.tar.gz no-f-in-the-stack/solution/handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-no-f-in-the-stack_exploit no-f-in-the-stack/solution
	./test-solution.sh quals-no-f-in-the-stack

push-no-f-in-the-stack-remote: handouts/quals-no-f-in-the-stack-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-no-f-in-the-stack no-f-in-the-stack/challenge
	docker tag livectf:quals-no-f-in-the-stack localhost:6000/b4f31f6edb2fdec8-no-f-in-the-stack:latest
	docker push localhost:6000/b4f31f6edb2fdec8-no-f-in-the-stack:latest
	gcloud storage cp handouts/quals-no-f-in-the-stack-handout.tar.gz 'gs://livectf25-challenges/no-f-in-the-stack.tgz'

push-no-f-in-the-stack-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-no-f-in-the-stack no-f-in-the-stack/challenge
	docker tag livectf:quals-no-f-in-the-stack localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# unwind-me-maybe

.PHONY: challenge-unwind-me-maybe
challenge-unwind-me-maybe: handouts/quals-unwind-me-maybe-handout.tar.gz

handouts/quals-unwind-me-maybe-handout.tar.gz: $(shell find unwind-me-maybe/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-unwind-me-maybe unwind-me-maybe/challenge
	./extract-handout.sh quals-unwind-me-maybe

.PHONY: run-unwind-me-maybe
run-unwind-me-maybe: challenge-unwind-me-maybe
	./test-run.sh quals-unwind-me-maybe

.PHONY: solution-unwind-me-maybe
solution-unwind-me-maybe: challenge-unwind-me-maybe $(shell find unwind-me-maybe/solution -type f)
	cp handouts/quals-unwind-me-maybe-handout.tar.gz unwind-me-maybe/solution/handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-unwind-me-maybe_exploit unwind-me-maybe/solution
	./test-solution.sh quals-unwind-me-maybe

push-unwind-me-maybe-remote: handouts/quals-unwind-me-maybe-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-unwind-me-maybe unwind-me-maybe/challenge
	docker tag livectf:quals-unwind-me-maybe localhost:6000/b4f31f6edb2fdec8-unwind-me-maybe:latest
	docker push localhost:6000/b4f31f6edb2fdec8-unwind-me-maybe:latest
	gcloud storage cp handouts/quals-unwind-me-maybe-handout.tar.gz 'gs://livectf25-challenges/unwind-me-maybe.tgz'

push-unwind-me-maybe-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-unwind-me-maybe unwind-me-maybe/challenge
	docker tag livectf:quals-unwind-me-maybe localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# ropably

.PHONY: challenge-ropably
challenge-ropably: handouts/quals-ropably-handout.tar.gz

handouts/quals-ropably-handout.tar.gz: $(shell find ropably/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-ropably ropably/challenge
	./extract-handout.sh quals-ropably

.PHONY: run-ropably
run-ropably: challenge-ropably
	./test-run.sh quals-ropably

.PHONY: solution-ropably
solution-ropably: challenge-ropably $(shell find ropably/solution -type f)
	cp handouts/quals-ropably-handout.tar.gz ropably/solution/handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-ropably_exploit ropably/solution
	./test-solution.sh quals-ropably

push-ropably-remote: handouts/quals-ropably-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-ropably ropably/challenge
	docker tag livectf:quals-ropably localhost:6000/b4f31f6edb2fdec8-ropably:latest
	docker push localhost:6000/b4f31f6edb2fdec8-ropably:latest
	gcloud storage cp handouts/quals-ropably-handout.tar.gz 'gs://livectf25-challenges/ropably.tgz'

push-ropably-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-ropably ropably/challenge
	docker tag livectf:quals-ropably localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# multi-level-model-marketing

.PHONY: challenge-multi-level-model-marketing
challenge-multi-level-model-marketing: handouts/quals-multi-level-model-marketing-handout.tar.gz

handouts/quals-multi-level-model-marketing-handout.tar.gz: $(shell find multi-level-model-marketing/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-multi-level-model-marketing multi-level-model-marketing/challenge
	./extract-handout.sh quals-multi-level-model-marketing

.PHONY: run-multi-level-model-marketing
run-multi-level-model-marketing: challenge-multi-level-model-marketing
	./test-run.sh quals-multi-level-model-marketing

.PHONY: solution-multi-level-model-marketing
solution-multi-level-model-marketing: challenge-multi-level-model-marketing $(shell find multi-level-model-marketing/solution -type f)
	cp handouts/quals-multi-level-model-marketing-handout.tar.gz multi-level-model-marketing/solution/handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-multi-level-model-marketing_exploit multi-level-model-marketing/solution
	./test-solution.sh quals-multi-level-model-marketing

push-multi-level-model-marketing-remote: handouts/quals-multi-level-model-marketing-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-multi-level-model-marketing multi-level-model-marketing/challenge
	docker tag livectf:quals-multi-level-model-marketing localhost:6000/b4f31f6edb2fdec8-multi-level-model-marketing:latest
	docker push localhost:6000/b4f31f6edb2fdec8-multi-level-model-marketing:latest
	gcloud storage cp handouts/quals-multi-level-model-marketing-handout.tar.gz 'gs://livectf25-challenges/multi-level-model-marketing.tgz'

push-multi-level-model-marketing-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-multi-level-model-marketing multi-level-model-marketing/challenge
	docker tag livectf:quals-multi-level-model-marketing localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# n-buns

.PHONY: challenge-n-buns
challenge-n-buns: handouts/quals-n-buns-handout.tar.gz

handouts/quals-n-buns-handout.tar.gz: $(shell find n-buns/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-n-buns n-buns/challenge
	./extract-handout.sh quals-n-buns

.PHONY: run-n-buns
run-n-buns: challenge-n-buns
	./test-run.sh quals-n-buns

.PHONY: solution-n-buns
solution-n-buns: challenge-n-buns $(shell find n-buns/solution -type f)
	cp handouts/quals-n-buns-handout.tar.gz n-buns/solution/handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-n-buns_exploit n-buns/solution
	./test-solution.sh quals-n-buns

push-n-buns-remote: handouts/quals-n-buns-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-n-buns n-buns/challenge
	docker tag livectf:quals-n-buns localhost:6000/b4f31f6edb2fdec8-n-buns:latest
	docker push localhost:6000/b4f31f6edb2fdec8-n-buns:latest
	gcloud storage cp handouts/quals-n-buns-handout.tar.gz 'gs://livectf25-challenges/n-buns.tgz'

push-n-buns-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-n-buns n-buns/challenge
	docker tag livectf:quals-n-buns localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################

# todo: put real chals here
push-test-challenges-local:
	docker tag livectf:quals-test-challenge 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker tag livectf:quals-test-challenge 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_the_cool_challenge:latest
	docker push 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_the_cool_challenge:latest
	docker tag livectf:quals-test-challenge 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_difficult_challenge:latest
	docker push 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_difficult_challenge:latest
	docker tag livectf:quals-test-challenge 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_doom:latest
	docker push 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_doom:latest
