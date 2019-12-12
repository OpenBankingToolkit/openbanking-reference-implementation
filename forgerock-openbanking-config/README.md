# OBRI Microservice Information - config

name:                 | config
------------          | -------------
description:          | [Spring Cloud Config Server](https://cloud.spring.io/spring-cloud-config/single/spring-cloud-config.html) - *"Spring Cloud Config provides server-side and client-side support for externalized configuration in a distributed system. With the Config Server, you have a central place to manage external properties for applications across all environments."*
status:               | stable
dependencies:         | none
database:             | none
special requirements: | SSH Keypair which is authorized to acccess a given git repo. The git server hostname must be added to SSH known hosts (ssh-keyscan) before this service starts, otherwise the service will fail.
startup order:        | **All microservices depend on this service**, it must be available before all other services start.
exposed externally:   | no, must not be exposed.
https:                | no
security considerations: | There is no authN configured on this service, configuration can be downloaded by anyone with network connectivity. 

The config server has two modes of running which can be toggled by the spring profile `-Dspring.profiles.active=native,console-logging`. The default profile is `composite`.
1. native - Uses [local configuration](../forgerock-openbanking-config)
1. composite - Pulls configuration from multiple git repos and merges them. The order the git repos are defined will control the priority of the configuration.

## Composite configuration
The composite configuration allows overriding of config. This means branded configuration can be added. The way to do this is via adding a JVM argument `git.uri.branded` with reference to a git repository.
Take https://github.com/ForgeCloud/ob-config-obie for an example. We could override the default configuration like so `-Dgit.uri.branded=git@github.com:ForgeCloud/ob-config-obie.git`

The structure of the repository should be:
```
.
└── forgerock-openbanking-config
    └── forgerock-openbanking-git-config
        ├── application-alphabank.yml
        ├── application-betabank.yml
        ├── application.yml
        ├── jwkms
        │   ├── application-alphabank.yml
        │   ├── application-betabank.yml
        │   └── application.yml
        └── rs
            └── rs-api
                ├── application-alphabank.yml
                ├── application-betabank.yml
                └── application.yml
```