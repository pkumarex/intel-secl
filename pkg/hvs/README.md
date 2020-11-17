# Intel<sup>®</sup> Security Libraries for Data Center  - HVS
#### The Intel<sup>®</sup> SecL - DC HVS component performs remote attestation of physical servers, comparing Intel<sup>®</sup> TXT measurements of BIOS, OS, Asset Tag, and other components against a database of known-good values. The attested trust status of each server is used to make policy decisions for workload placement. As a server boots, Intel<sup>®</sup> TXT begins extending measurements to a Trusted Platform Module (TPM). Each chain of trust component is measured, and these measurements are remotely verified using the Attestation Server.

## Key features
- Remote attestation of platforms
- Provides storage for good known values for platforms
- Provides trust status evaluation of platforms against good known values
- RESTful APIs for easy and versatile access to above features

## Build HVS

- Git clone the `HVS`
- Run scripts to build the `HVS`

```shell
git clone https://github.com/intel-secl/intel-secl.git
cd intel-secl
make hvs-installer
```

# Links
 - Use [Automated Build Steps](https://01.org/intel-secl/documentation/build-installation-scripts) to build all repositories in one go, this will also provide provision to install prerequisites and would handle order and version of dependent repositories.

***Note:** Automated script would install a specific version of the build tools, which might be different than the one you are currently using*
 - [Product Documentation](https://01.org/intel-secl/documentation/intel%C2%AE-secl-dc-product-guide)
