GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
ifeq ($(PROXY_EXISTS),1)
	DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
endif

TARGETS = cms kbs ihub hvs aas

$(TARGETS):
	cd cmd/$@ && env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off GOPROXY=direct \
		go build -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/$@/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/$@/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/$@/version.GitHash=$(GITCOMMIT)" -o $@

kbs:
	mkdir -p installer
	cp /usr/local/lib/libkmip.so.0.2 installer/libkmip.so.0.2
	cd cmd/kbs && env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off GOPROXY=direct \
		go build -gcflags=all="-N -l" \
		-ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.GitHash=$(GITCOMMIT)" -o kbs


%-installer: %
	mkdir -p installer
	cp -r build/linux/$*/* installer/
	chmod +x installer/install.sh
	cp cmd/$*/$* installer/$*
	makeself installer deployments/installer/$*-$(VERSION).bin "$* $(VERSION)" ./install.sh
	rm -rf installer

%-docker: %
ifeq ($(PROXY_EXISTS),1)
	docker build ${DOCKER_PROXY_FLAGS} -f build/image/Dockerfile-$* -t isecl/$*:$(VERSION) .
else
	docker build -f build/image/Dockerfile-$* -t isecl/$*:$(VERSION) .
endif
	docker save isecl/$*:$(VERSION) > deployments/docker/docker-$*-$(VERSION)-$(GITCOMMIT).tar

%-swagger:
	mkdir -p docs/swagger
	swagger generate spec -w ./docs/shared/$* -o ./docs/swagger/$*-openapi.yml
	swagger validate ./docs/swagger/$*-openapi.yml

installer: $(patsubst %, %-installer, $(TARGETS)) authservice-installer aas-manager
	

docker: $(patsubst %, %-docker, $(TARGETS))

kbs-docker: kbs
	cp /usr/local/lib/libkmip.so.0.2 build/image/
	docker build . -f build/image/Dockerfile-kbs -t isecl/kbs:$(VERSION)
	docker save isecl/kbs:$(VERSION) > deployments/docker/docker-kbs-$(VERSION)-$(GITCOMMIT).tar

authservice: aas
	mv cmd/aas/aas cmd/aas/authservice

authservice-installer: authservice
	mkdir -p installer
	cp build/linux/aas/* installer/
	chmod +x installer/install.sh
	cp cmd/aas/authservice installer/authservice
	makeself installer deployments/installer/authservice-$(VERSION).bin "authservice $(VERSION)" ./install.sh
	rm -rf installer

aas-manager:
	cd tools/aas-manager && env GOOS=linux GOSUMDB=off GOPROXY=direct go build -o populate-users
	cp tools/aas-manager/populate-users deployments/installer/populate-users.sh
	cp build/linux/aas/install_pgdb.sh deployments/installer/install_pgdb.sh
	cp build/linux/aas/create_db.sh deployments/installer/create_db.sh
	chmod +x deployments/installer/install_pgdb.sh
	chmod +x deployments/installer/create_db.sh

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean installer test

clean:
	rm -f cover.*
	rm -rf deployments/installer/*.bin
	rm -rf deployments/docker/*.tar

.PHONY: installer test all clean kbs-docker aas-manager kbs authservice authservice-installer
