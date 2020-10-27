# Intel<sup>®</sup> SecL-DC
This repository is planned to be monorepo to hold all services and libraries.

## System Requirements
- RHEL 8.1
- Epel 8 Repo
- Proxy settings if applicable

## Software requirements
- git
- makeself
- `go` version >= `go1.13.0` & <= `go1.14.4``

# Step By Step Build Instructions
## Install required shell commands
Please make sure that you have the right `http proxy` settings if you are behind a proxy
```shell
export HTTP_PROXY=http://<proxy>:<port>
export HTTPS_PROXY=https://<proxy>:<port>
```
### Install tools from `yum`
```shell
$ sudo yum install -y wget git makeself
```

### Install `go` version >= `go1.13.0` & <= `go1.14.4`
Services requires Go version  > 1.12.1 that has support for `go modules`. The build was validated with the latest version go1.14.4 of `go`. It is recommended that you use go1.14.4 version of `go`. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz
tar -xzf go1.14.4.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

# Generation of Binary
Use command make <component_name> to build component and make <component_name>-installer to generate binary.
Example:

```
$ make hvs
% make hvs-installer
% make ihub-installer
```

# Swagger Document Creation
Use command make swagger to generate swagger/openapi documentation for APIs,

Pre-requisite:
```
$ wget https://github.com/go-swagger/go-swagger/releases/download/v0.21.0/swagger_linux_amd64 -O /usr/local/bin/swagger
$ chmod +x /usr/local/bin/swagger
```  

Command to generate swagger documentation:
```
$ make swagger
```