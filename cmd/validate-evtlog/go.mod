module main

go 1.25.0

require github.com/zededa/evepcr v0.1.0

require (
	github.com/canonical/go-sp800.108-kdf v0.0.0-20210314145419-a3359f2d21b9 // indirect
	github.com/canonical/go-tpm2 v1.0.1-0.20230302101824-929183e212cc // indirect
	github.com/lf-edge/eve-tpmea v0.1.1-0.20260414082129-2c939de91696 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
	golang.org/x/sys v0.1.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace github.com/zededa/evepcr => ../../
