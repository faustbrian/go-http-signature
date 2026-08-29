BENCH_TIME ?= 100ms
BENCH_COUNT ?= 10

.PHONY: benchmark conformance docs interoperability supplemental

supplemental:
	GOWORK=off go test -mod=readonly -race . \
		-run '^(TestMemoryReplayStoreAllowsExactlyOneConcurrentConsumer|TestMemoryReplayStoreCancellationBoundaries)$$' -count=100
	GOWORK=off go test -mod=readonly . \
		-run '^(TestSignerCreatesDeterministicFieldsAcceptedByVerifier|TestMemoryReplayStoreAtomicallyConsumesNonceUntilExpiration)$$' -count=1000
	GOWORK=off go test -mod=readonly ./... \
		-run 'FailsClosed|BoundaryFailures|RejectsEach|Sanitizes|CallbackFailures' -count=1
	GOWORK=off go test -mod=readonly -race . \
		-run '^TestVerifierLifecycle' -count=20
	./scripts/check-clean-consumer.sh

docs:
	./scripts/check-docs.sh

conformance:
	./scripts/check-spec-sources.sh
	./scripts/check-conformance.sh
	GOWORK=off go test -mod=readonly ./... \
		-run 'RFC|RegisteredAlgorithms|DigestPreferences|RequestTarget' -count=1

interoperability:
	./scripts/check-interoperability.sh

benchmark:
	GOWORK=off go test -mod=readonly ./... \
		-run '^$$' -bench . -benchmem -benchtime=$(BENCH_TIME)
	$(MAKE) -C benchmarks/comparison benchmark \
		BENCH_TIME=$(BENCH_TIME) BENCH_COUNT=$(BENCH_COUNT)
