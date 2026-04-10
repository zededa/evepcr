ROOTFS_IMG := testdata/rootfs/rootfs.img
ROOTFS_URL := https://github.com/zededa/tpm-event-verifier/releases/download/v0.0.0/rootfs.img

.PHONY: test build clean

build:
	go build ./...
	cd cmd/predict && go build .
	cd cmd/validate-evtlog && go build .
	cd cmd/gen-policy && go build .
	cd cmd/rootfs-hash && go build .

$(ROOTFS_IMG):
	@echo "Downloading rootfs test fixture..."
	curl -fsSL -o $@ $(ROOTFS_URL)

test: $(ROOTFS_IMG)
	go test -v ./...

clean:
	rm -f $(ROOTFS_IMG)
	rm -f cmd/predict/main 		\
	cmd/validate-evtlog/main 	\
	cmd/gen-policy/main 		\
	cmd/rootfs-hash/main