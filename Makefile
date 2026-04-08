ROOTFS_IMG := testdata/rootfs/rootfs.img
ROOTFS_URL := https://github.com/zededa/tpm-event-verifier/releases/download/v0.0.0/rootfs.img

.PHONY: test build clean

build:
	go build ./...
	cd cmd/eve-predict && go build .
	cd cmd/eve-validate && go build .

$(ROOTFS_IMG):
	@echo "Downloading rootfs test fixture..."
	curl -fsSL -o $@ $(ROOTFS_URL)

test: $(ROOTFS_IMG)
	go test -v ./...

clean:
	rm -f $(ROOTFS_IMG)
	rm -f cmd/eve-predict/main cmd/eve-validate/main cmd/eve-validate/eve-validate
