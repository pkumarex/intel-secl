GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: installer test all clean

cms:
	cd cmd/cms && env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/cms/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/cms/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/cms/version.GitHash=$(GITCOMMIT)" -o cms

cms-installer: cms
	mkdir -p installer
	cp build/linux/cms/cms.service installer/cms.service
	cp build/linux/cms/install.sh installer/install.sh && chmod +x installer/install.sh
	cp cmd/cms/cms installer/cms
	makeself installer deployments/installer/cms-$(VERSION).bin "Certificate Management Service $(VERSION)" ./install.sh
	rm -rf installer

kbs:
	cd cmd/kbs && env CGO_CFLAGS_ALLOW="-f.*" GOOS=linux GOSUMDB=off GOPROXY=direct go build -gcflags=all="-N -l" -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.GitHash=$(GITCOMMIT)" -o kbs

kbs-installer: kbs
	mkdir -p installer
	cp pkg/kbs/dist/linux/kbs.service installer/kbs.service
	cp pkg/kbs/dist/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	cp cmd/kbs/kbs installer/kbs
	cp /usr/local/lib/libkmip.so.0.2 installer/libkmip.so.0.2
	makeself installer deployments/installer/kbs-$(VERSION).bin "KBS $(VERSION)" ./install.sh
	rm -rf installer

ihub:
	cd cmd/ihub && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/ihub/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/ihub/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/ihub/version.GitHash=$(GITCOMMIT)" -o ihub

ihub-installer: ihub
	mkdir -p installer
	cp pkg/ihub/dist/linux/ihub.service installer/ihub.service
	cp pkg/ihub/dist/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	cp cmd/ihub/ihub installer/ihub
	makeself installer deployments/installer/ihub-$(VERSION).bin "IHub $(VERSION)" ./install.sh
	rm -rf installer

hvs:
	cd cmd/hvs && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/hvs/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/hvs/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/hvs/version.GitHash=$(GITCOMMIT)" -o hvs

hvs-installer: hvs
	mkdir -p installer
	cp build/linux/hvs/EndorsementCA-external.pem installer/EndorsementCA-external.pem
	cp build/linux/hvs/hvs.service installer/hvs.service
	cp build/linux/hvs/install.sh installer/install.sh && chmod +x installer/install.sh
	cp cmd/hvs/hvs installer/hvs
	makeself installer deployments/installer/hvs-$(VERSION).bin "HVS $(VERSION)" ./install.sh
	rm -rf installer

aas:
	cd cmd/authservice && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/aas/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/aas/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/aas/version.GitHash=$(GITCOMMIT)" -o authservice

aas-manager:
	cd build/linux/aas/aas-manager && env GOOS=linux GOSUMDB=off GOPROXY=direct go build -o populate-users

aas-installer: aas aas-manager
	mkdir -p installer
	cp build/linux/aas/authservice.service installer/authservice.service
	cp build/linux/aas/install.sh installer/install.sh && chmod +x installer/install.sh
	cp build/linux/aas/db_rotation.sql installer/db_rotation.sql
	cp cmd/authservice/authservice installer/authservice
	makeself installer deployments/installer/authservice-$(VERSION).bin "AAS $(VERSION)" ./install.sh
	cp build/linux/aas/install_pgdb.sh deployments/installer/install_pgdb.sh && chmod +x deployments/installer/install_pgdb.sh
	cp build/linux/aas/create_db.sh deployments/installer/create_db.sh && chmod +x deployments/installer/create_db.sh
	mv build/linux/aas/aas-manager/populate-users deployments/installer/populate-users.sh && chmod +x deployments/installer/populate-users.sh
	rm -rf installer

installer: cms-installer aas-installer hvs-installer ihub-installer kbs-installer

aas-docker: aas
	mkdir -p out
	cp cmd/authservice/authservice out/
	cp build/image/entrypoint-aas.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/authservice:$(VERSION) --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy} -f build/image/Dockerfile-aas ./out
	docker save isecl/authservice:$(VERSION) > deployments/docker/docker-authservice-$(VERSION)-$(GITCOMMIT).tar
	rm -rf out

ihub-docker: ihub
	docker build . -f build/image/Dockerfile-ihub -t isecl/ihub:$(VERSION)
	docker save isecl/ihub:$(VERSION) > deployments/docker/docker-ihub-$(VERSION)-$(GITCOMMIT).tar

hvs-docker: hvs
	docker build . -f build/image/Dockerfile-hvs -t isecl/hvs:$(VERSION)
	docker save isecl/hvs:$(VERSION) > deployments/docker/docker-hvs-$(VERSION)-$(GITCOMMIT).tar


kbs-docker: kbs
	cp /usr/local/lib/libkmip.so.0.2 build/image/
	docker build . -f build/image/Dockerfile-kbs -t isecl/kbs:$(VERSION)
	docker save isecl/kbs:$(VERSION) > deployments/docker/docker-kbs-$(VERSION)-$(GITCOMMIT).tar

cms-docker: cms
	mkdir -p out/
	cp cmd/cms/cms out/
	cp build/image/entrypoint-cms.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
ifeq ($(PROXY_EXISTS),1)
	docker build -t isecl/cms:$(VERSION) --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy} -f ./build/image/Dockerfile-cms ./out
else
	docker build -t isecl/cms:$(VERSION) -f ./build/image/Dockerfile-cms ./out
endif
	docker save isecl/cms:$(VERSION) > deployments/docker/docker-cms-$(VERSION)-$(GITCOMMIT).tar
	rm -rf out/

kbs-swagger:
	mkdir -p docs/swagger
	swagger generate spec -w ./docs/shared/kbs -o ./docs/swagger/kbs-openapi.yml
	swagger validate ./docs/swagger/kbs-openapi.yml

hvs-swagger:
	mkdir -p docs/swagger
	swagger generate spec -w ./docs/shared/hvs -o ./docs/swagger/hvs-openapi.yml
	swagger validate ./docs/swagger/hvs-openapi.yml

aas-swagger:
	mkdir -p docs/swagger
	swagger generate spec -w ./docs/shared/aas -o ./docs/swagger/aas-openapi.yml
	swagger validate ./docs/swagger/aas-openapi.yml

cms-swagger:
	mkdir -p docs/swagger
	swagger generate spec -w ./docs/shared/cms -o ./docs/swagger/cms-openapi.yml
	swagger validate ./docs/swagger/cms-openapi.yml

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean installer test

clean:
	rm -f cover.*
	rm -rf deployments/installer/*.bin
	rm -rf deployments/docker/*.tar
