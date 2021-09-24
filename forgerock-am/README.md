# Open Banking AM docker image (local environment)
## Introduction
> ⚠ Guide only for FR developers with the proper permisions to get the binaries

## Get the binaries
To build the Open Banking AM docker image on local will be necessary download the binaries from GC bucket
```shell
cd openbanking-reference-implementation
```
```shell
gsutil rsync gs://ob-forgerock-binaries/openam-local-binaries forgerock-am/_binaries
```
### Current AM war version files
- OpenAM-6.5.1-9f4e82458a.war
- Amster-6.5.1.zip

## Current Customer Patch
> The customer patch is not needed anymore because 
> the AM.war builds for Open Banking is from the customer branch with all patches integrated
- openbanking-1-2-tpatch.zip

## Docker compose
Edit `docker-compose.yml` if necessary to change the arguments:
- **AM_WAR_NAME**: "*OpenAM-X.X.X.war*"
- **AMSTER_ZIP**: "*Amster-X.X.X.zip*"


The Docker compose command will build the AM image and start the container:
```
docker-compose up
```
