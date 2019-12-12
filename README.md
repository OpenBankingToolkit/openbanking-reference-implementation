[<img src="https://raw.githubusercontent.com/ForgeRock/forgerock-logo-dev/master/Logo-fr-dev.png" align="right" width="220px"/>](https://developer.forgerock.com/)

| |Current Status|
|---|---|
|License|![license](https://img.shields.io/github/license/ACRA/acra.svg)|

**_This repository is part of the Open Banking Tool kit. If you just landed to that repository looking for our tool kit,_
_we recommend having a first read to_ https://github.com/OpenBankingToolkit/openbanking-toolkit**



# Open Banking Reference Implementation - Backend

## How to install the backend development environment

### Setting up Maven

Download and install Maven settings.xml file by running the command below and substituting in your backstage username and password.

```bash
curl -u $BACKSTAGE_USERNAME http://maven.forgerock.org/repo/private-releases/settings.xml > ~/.m2/settings.xml
```

### Compile

#### Docker set up

You'll need to log in to the codefresh docker registry.

1. You'll need an API which you can get by following https://codefresh.io/docs/docs/docker-registries/codefresh-registry/#generate-cfcr-login-token
1. Login by following https://codefresh.io/docs/docs/docker-registries/codefresh-registry/#generate-cfcr-login-token

#### Building project and docker images

Just run `mvn install`. This will build the images but if you want to skip them, run `mvn install -Ddockerfile.skip`

### Setup the host files

You will need to create some new hostnames for the application.

Ensure your hosts file looks like [hosts-local](./hosts-local). Use Gas mask for managing your hostnames.

### SSL: Adding self-signed CA for dev environment

Follow the steps for all the certificates in the folder `certificates/`.

#### Install certificate in our truststore

1. Click on it and your mac os will show you the system config view.
1. Add it and mark it as trusted, as follow:

![](images/installCA.png?raw=true)

#### Install the CA in FireFox truststore

For a reason, Firefox has decided to not read the system truststore but to have it's own. Therefore,
you need to add the certificates in firefox trusted certificates.

Find the certificate sections in Privacy & Security

![](images/firefoxCertSetting.png?raw=true)

Import the certificates.
You should then have the certificates in the trusted CA list, as follow:

![](images/firefoxImportCA.png?raw=true)

### Install the unlimited strength file extension

You will need to install this extension as described in https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters

### Setup jwkstore

1. `sudo mkdir -p /opt/openbanking/jwkms/`
1. `sudo chown -R $USER /opt/openbanking`
1. `cp keystore/jwkstore/jwksstore.pfx /opt/openbanking/jwkms/jwksstore.pfx`

## How to run the development environment

- Start Docker & Kubernetes
- Start run configurations in the following order
  - "Run Mongo"
  - "K8s proxy"
  - backstage/Openbanking-config
  - backstage/Openbanking-jwkms
  - Directory/Openbanking-directory
  From this point, the order doesn't matter anymore
  
You don't need to run all the microservices all the time. Depending on what you are working on,
you can choose to enable a subset of the microservices.

## Re-generate the self-signed certificate

DO NOT RE-GENERATE THE SELF-SIGNED CERTIFICATE UNLESS YOU REALLY NEED TO.

If for a reason, you need to re-generate all the self-signed certificate (a new micro-services that needs a key for ex),
you should use the keystore/Makefile

It's a usual makefile which will help you creating the keys.
A short usage would be to use the 'all' command as follow

`make all`
