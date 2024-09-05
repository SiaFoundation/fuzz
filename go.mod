module go.sia.tech/fuzz

go 1.22.0

replace go.sia.tech/core => ./core

require (
	github.com/brunoga/deep v1.2.4
	go.sia.tech/core v0.4.6
	go.sia.tech/coreutils v0.3.3-0.20240903190934-0dd7ac18e90f
	lukechampine.com/flagg v1.1.1
)

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	go.etcd.io/bbolt v1.3.11 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	lukechampine.com/frand v1.4.2 // indirect
)
