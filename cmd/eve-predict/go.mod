module main

go 1.25.0

replace eve_pcr_prediction => ../../

replace github.com/google/go-attestation => ../../deps/go-attestation

require eve_pcr_prediction v0.0.0-00010101000000-000000000000

require (
	github.com/google/go-attestation v0.0.0-00010101000000-000000000000 // indirect
	github.com/google/go-tpm v0.9.5 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
