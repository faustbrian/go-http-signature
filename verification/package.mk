GO ?= go

.PHONY: benchmark conformance docs interoperability package-contract

benchmark:
	$(GO) test -mod=readonly ./... -run '^$$' -bench . -benchmem -benchtime=100ms
	$(MAKE) -C benchmarks/comparison benchmark BENCH_TIME=100ms BENCH_COUNT=10

conformance:
	./scripts/check-spec-sources.sh
	./scripts/check-conformance.sh
	$(GO) test -mod=readonly ./... -run 'RFC|RegisteredAlgorithms|DigestPreferences|RequestTarget' -count=1

docs:
	./scripts/check-docs.sh

interoperability:
	./scripts/check-interoperability.sh

package-contract:
	$(GO) test -mod=readonly -race . -run '^(TestMemoryReplayStoreAllowsExactlyOneConcurrentConsumer|TestMemoryReplayStoreCancellationBoundaries)$$' -count=100
	$(GO) test -mod=readonly . -run '^(TestSignerCreatesDeterministicFieldsAcceptedByVerifier|TestMemoryReplayStoreAtomicallyConsumesNonceUntilExpiration)$$' -count=1000
	$(GO) test -mod=readonly ./... -run '(FailsClosed|BoundaryFailures|RejectsEach|Sanitizes|CallbackFailures)' -count=1
	$(GO) test -mod=readonly -race . -run '^TestVerifierLifecycle' -count=20
	./scripts/check-clean-consumer.sh
