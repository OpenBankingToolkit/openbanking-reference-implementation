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
Source: [patches/6.5.5.1/openbanking](https://stash.forgerock.org/projects/OPENAM/repos/openam-customers/browse?at=refs%2Fheads%2Fpatches%2F6.5.5.1%2Fopenbanking)
- OpenAM-6.5.5-a7dd57885e7.war
- Amster-6.5.5-a7dd57885e7.zip

> The AM.war builds for Open Banking is from the customer branch with all patches integrated

**How to when AM version changed**
- Update ./forgerock-am/amster/config/global/Platform.json
- Update ./forgerock-am/Dockerfile (`com.iplanet.am.buildVersion` value)
- Update ./forgerock-am/README.md file
- Update kube configuration [ob-kube-am-config am](https://github.com/ForgeCloud/ob-kube-am-config/blob/master/docker/am/Dockerfile)
- Update kube configuration [ob-kube-am-config amster](https://github.com/ForgeCloud/ob-kube-am-config/blob/master/docker/amster/Dockerfile)
## Docker compose
Edit `docker-compose.yml` if necessary to change the arguments:
- **AM_WAR_NAME**: "*OpenAM-X.X.X.war*"
- **AMSTER_ZIP**: "*Amster-X.X.X.zip*"


The Docker compose command will build the AM image and start the container:
```
docker-compose up
```
