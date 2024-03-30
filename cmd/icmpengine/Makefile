#
# icmpengine/cmd/icmpengine/Makefile
#
COMMIT=$(shell /bin/git describe --always)
DATE=$(shell /bin/date -u +"%Y-%m-%d-%H:%M")
BINARY := icmpengine

#GITLOG=$(shell /bin/git log -n1 --pretty='%h')
#VERSION=$(shell /bin/git describe --abbrev=0 --tags)

all: clean build version

#	-ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"
build:
	CGO_ENABLED=0 go build -ldflags "-X main.commit=${COMMIT} -X main.date=${DATE}" -o ./${BINARY} ./${BINARY}.go

clean:
	[ -f ${BINARY} ] && /bin/rm -rf ./${BINARY} || true

version:
	./${BINARY} --version

lo:
	./${BINARY} --dest 127.0.0.1,::1
	./${BINARY} --dest 127.0.0.1,::1 --count 100

los:
	./${BINARY} --dest 127.0.0.1,::1 --splay

google:
	./${BINARY} --dest 8.8.8.8,8.8.4.4

race:
	go run -race ./${BINARY}.go

test:
	go test
