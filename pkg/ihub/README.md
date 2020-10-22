# Integration Hub

`Integration Hub Service` is a web service that helps in sending updated trust informations to the orchestrator endpoints. Integration Hub fetches attestation details from HVS and updates it to the endpoint orchestrators like Openstack/Kubernetes.
## Key features
- Retrieves attestation details at configured interval from the Host Verification service.
- Pushes attestation details to configured orchestrators e.g OpenStack/Kubernetes

## System Requirements
- RHEL 8.1
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements
- git
- makeself
- `go` version >= `go1.12.1` & <= `go1.14.1`

# Step By Step Build Instructions

## Install required shell commands
Please make sure that you have the right `http proxy` settings if you are behind a proxy
```shell
export HTTP_PROXY=http://<proxy>:<port>
export HTTPS_PROXY=https://<proxy>:<port>
```

### Install tools from `yum`
```shell
sudo yum install -y git wget makeself
```

### Install `go` version >= `go1.12.1` & <= `go1.14.1`
The `Integration Hub` requires Go version 1.12.1 that has support for `go modules`. The build was validated with the latest version 1.14.1 of `go`. It is recommended that you use 1.14.1 version of `go`. More recent versions may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.1.linux-amd64.tar.gz
tar -xzf go1.14.1.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build Integration Hub
- Git clone the Mono-Repo which includes Integration Hub
- Run below scripts to build the Integration hub

```shell
git clone https://gitlab.devtools.intel.com/sst/isecl/intel-secl
cd intel-isecl
make ihub-installer
```

### Deploy
```console
> ./ihub-*.bin
```

### Manage service
* Start service
    * ihub start
* Stop service
    * ihub stop
* Status of service
    * ihub status

### Direct dependencies

| Name        | Repo URL                            | Minimum Version Required                          |
| ----------- | ------------------------------------| :------------------------------------------------ |
| jwt-go      | github.com/Waterdrips/jwt-go        | v3.2.1-0.20200915121943-f6506928b72e+incompatible |
| uuid        | github.com/google/uuid              | v1.1.1                                            |
| mux         | github.com/gorilla/mux              | v1.7.3                                            |
| logrus      | github.com/sirupsen/logrus          | v1.4.0                                            |
| goxmldsig   | github.com/russellhaering/goxmldsig | v0.0.0-20180430223755-7acd5e4a6ef7                | 
| errors      | github.com/pkg/errors               | v0.9.1                                            |
| testify     | github.com/stretchr/testify         | v1.2.2	                                        |
| yaml.v2     | gopkg.in/yaml.v2                    | v2.3.0                                            |


*Note: All dependencies are listed in go.mod*

# Links
 - Use [Automated Build Steps](https://01.org/intel-secl/documentation/build-installation-scripts) to build all repositories in one go, this will also provide provision to install prerequisites and would handle order and version of dependent repositories.

***Note:** Automated script would install a specific version of the build tools, which might be different than the one you are currently using*
 - [Product Documentation](https://01.org/intel-secl/documentation/intel%C2%AE-secl-dc-product-guide)

