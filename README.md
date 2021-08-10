[<img src="https://raw.githubusercontent.com/ForgeRock/forgerock-logo-dev/master/Logo-fr-dev.png" align="right" width="220px"/>](https://developer.forgerock.com/)

| |Current Status|
|---|---|
|Release|[![GitHub release (latest by date)](https://img.shields.io/github/v/release/OpenBankingToolkit/openbanking-reference-implementation.svg)](https://img.shields.io/github/v/release/OpenBankingToolkit/openbanking-reference-implementation)
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

Firefox does not read the system truststore but instead implements it's own. Therefore,
you need to add the certificates to firefox trusted certificates.

Find the certificate sections in Privacy & Security

![](images/firefoxCertSetting.png?raw=true)

Import the certificates.
You should then have the certificates in the trusted CA list, as follow:

![](images/firefoxImportCA.png?raw=true)

### Install the unlimited strength file extension

You will need to install this extension as described in https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters

### Setup the JWKMS' Trust Store

The jwkms (Json Web Key Management Services) micro service uses a trust store from which  it obtains two CA certificates, `obri-external-ca` and `obri-internal-ca`. These are used by the jwkms to;

- Sign the transport and signing certificates issued to a Third Party Provider application when it is registered with the Open Banking Directory. These certificates will be signed by the `obri-external-ca` certificate.

- Sign the transport and signing certificates issued to each micro service for the purpose of signing payloads etc. For example, the Open Banking Directory will be issued a signing certificate that is signed by the `obri-external-ca` certificate. This certificate will be used to sign SSAs issued by the directory.

  The `obri-external-ca` will appear as the issuer of certs described above.

  ```
  Issuer Name
  C (Country):	UK
  ST (County):	Avon
  L (Locality):	Bristol
  O (Organisation):	ForgeRock
  OU (Organisational Unit):	forgerock.financial
  CN (Common Name):	obri-external-ca
  ```

- Sign the Mutual Transport Layer Security certificates used by the micro services to communicate securely between each other. The subject of a presented MTLS certificate will also identify the micro service from which a call has been made.

  These internal certs will have the following issuer;

  ```
  Issuer Name
  C (Country):	UK
  ST (County):	Avon
  L (Locality):	Bristol
  O (Organisation):	ForgeRock
  OU (Organisational Unit):	forgerock.financial
  CN (Common Name):	obri-internal-ca
  ```

To make these keys available to the jwkms you will need to;

1. sudo mkdir -p /opt/openbanking/jwkms/`
1. `sudo chown -R $USER /opt/openbanking`
1. `cp keystore/jwkstore/jwksstore.pfx /opt/openbanking/jwkms/jwksstore.pfx`

## How to run the development environment

### Docker

To set up your source file ready to build an AM Docker image you will need to follow the instructions found here;
[forgerock-am readme](forgerock-am/README.md)

#### GCP credentials (only FR team members)
>The credentials are only accessible for forgerock team members, simulated default value for GCP credentials are set for customers.
> The test Get account statement file will return 404 - not found when simulated default value is used.

In the `docker-compose file` the service rs-store currently use a volume to access the GCP credentials set in the environment.
Setting the GCP credentials in local to use it in docker-compose `rs-store` service.
1. Copy the secret file `ob-gcr.json` from `ob-ci-secrets` repository to your path.
2. Create the env variable `GCP_CREDENTIALS` in your local system pointed to `ob-gcr.json`.
```shell
export GCP_CREDENTIALS=path/to/ob-gcr.json
```
#### Run with Docker compose
```shell
docker-compose up
```
#### Run with Docker compose profiles
**Compose Profiles**
> We use the directive profiles to select the enabled services to run.[Compose profiles documentation](https://docs.docker.com/compose/profiles/)

> Specific compose (`docker-compose-profiles.yml`) file to use the profiles.
> 
**Requirements to use compose profiles**
- Compose version >= 1.28
- MacOs users: upgrade docker desktop to 3.2.1 or later or used `brew` to install/upgrade it.
- Linux users [Install docs](https://docs.docker.com/compose/install/):
  - Alternatives
  ```shell
    pip install docker-compose
  ```
  ```shell 
    curl -L "https://github.com/docker/compose/releases/download/1.22.0/docker-compose-$(uname -s)-$(uname -m)" > ./docker-compose
    sudo mv ./docker-compose /usr/bin/docker-compose
    sudo chmod +x /usr/bin/docker-compose
  ```
**Run docker compose profiles**
- These services without profile will be run always, we treated them like as `mandatory services`
- Current Profiles:
  - _**all**_: Runs `all` profile platform services
    ```shell
    docker-compose -f docker-compose-profiles.yml --profile all up
    ```
  - _**metrics**_: Runs `mandatory` platform services and `metrics` profile services
    ```shell
    docker-compose -f docker-compose-profiles.yml --profile metrics up
    ```
  - _**analytics**_: Runs `mandatory` platform services and `analytics` profile services
    ```shell
    docker-compose -f docker-compose-profiles.yml --profile analytics up
    ```


### Kubernetes
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
