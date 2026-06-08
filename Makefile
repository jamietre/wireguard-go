CROSS_CC  = aarch64-linux-gnu-gcc
GOOS      = linux
GOARCH    = arm64
CGO       = 0

.PHONY: all wireguard-go wg clean

all: bin/wireguard-go bin/wg

bin/wireguard-go:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO) go build -o $@ .

bin/wg:
	$(MAKE) -C wireguard-tools/src CC=$(CROSS_CC) WITH_WGQUICK=no LDFLAGS="-static"
	cp wireguard-tools/src/wg $@

clean:
	rm -f bin/wireguard-go bin/wg
	$(MAKE) -C wireguard-tools/src clean
