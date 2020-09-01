# Open Banking AM docker image (local environment)
## Introduction
> ⚠ Guide only for FR developers with the proper permisions to get the binaries

## Get the binaries
To build the Open Banking AM docker image on local will be necessary download the binaries from GC bucket
```
gsutil rsync gs://ob-forgerock-binaries/openam-local-binaries forgerock-am/_binaries
```

## Current Customer Patch
- openbanking-1-2-tpatch.zip

## Docker compose
Edit `docker-compose.yml` if necessary to change the arguments:
- **AM_WAR_NAME**: "*OpenAM-X.X.X.war*"
- **AM_PATCH_ZIP**: "*openbanking-X-X-tpatch.zip*"
- **AMSTER_ZIP**: "*Amster-X.X.X.zip*"

The Docker compose command will build the AM image and start the container:
```
docker-compose up
```