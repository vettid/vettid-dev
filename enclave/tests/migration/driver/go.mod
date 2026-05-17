// The Tier-2 driver is its own Go module so its dependencies (the
// nats.go client, aws-sdk-go-v2 once we need it for S3/SSM assertions)
// don't leak into the enclave production build path. Kept on the same
// Go version as the enclave so a single toolchain serves both.
module github.com/vettid/vettid-dev/enclave/tests/migration/driver

go 1.25

require github.com/nats-io/nats.go v1.39.1

require (
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/nats-io/nkeys v0.4.10 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)
