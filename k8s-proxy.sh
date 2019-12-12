#!/usr/bin/env bash

(kubectl get pods -o name|grep fr-am| xargs -I{} kubectl port-forward {} 8443:8443 & kubectl get pods -o name|grep fr-am| xargs -I{} kubectl port-forward {} 5005:1043)