---
name: Deploy to a dev/integ cluster
about: Checklist for deploying to a dev or integ cluster
title: Deploy <VERSION> to Cluster <CLUSTER_NAME>
labels: "Customer: FR, Deployment"
assignees: ""
---

As an ASPSP I need ForgeRock to deploy the latest software onto my sandbox so that my TPP customers can test against my APIs.

## Acceptance criteria

- Task checklist below is completed for cluster

## Tasks

- [ ] Create or update tfvars file in ob-infra
- [ ] Run ob-infra pipeline
- [ ] Create 'ob-kube-am-config' branch from master
  - [ ] If you have custom AM cfg (LBG): Create/update '/env/am/obri-650/{cluster}'
- [ ] Re-generate secrets on 'ob-k8s-secrets' master branch
  - [ ] Copy existing secrets from the cluster already serving the domain for which the cluster is being created. e.g. if you creating a blue cluster and there is a green cluster you can copy the secrets from the green cluster. The point here is that the secrets for a specifc domain should not change between deployments.
  - [ ] Run the `ob-k8s-secrets/bin/gen.sh <path to cluster secrets>` command and review
  - [ ] Commit any changed and newly created files. 
- [ ] Update 'ob-deploy' master branch
  - [ ] Create cluster directory (if it doesn't already exist)
  - [ ] Check '.env' has correct values for cluster including the `TAG`
  - [ ] Check release.json has correct release versions of software
  - [ ] Check release.json has any new microservices since last release
  - [ ] Check global.yaml has correct Spring profiles and UI template
  - [ ] Check global.yaml has complete 'hostAliases' config
  - [ ] Create new RC tag
  - [ ] Check 'core-releases.json' chart versions against versions in 'master-dev'
  - [ ] For existing cluster with data: Force upgrade of any changed data (e.g. metrics) by setting 'force upgrade' flag
  - [ ] Create/update 'delta-requirements.yaml' with IP (from GCE/VPC/External IPs) and correct domain
- [ ] Create ob-deploy pipeline and check 'CERT_ISSUER=dummyIssuer' is in codefresh env values
      ------------------ Everything above must be complete before next step ----------------
- [ ] Run ob-deploy pipeline
- [ ] If Required: Backup from old env and restore to new one
  - [ ] Scale down spring apps
  - [ ] Do data restore
  - [ ] Scale up spring apps
  - [ ] Re-run ob-deploy pipeline to force data upgrade
  - [ ] Remove any 'force upgrade' flags from ob-deploy
- [ ] Testing
  - [ ] Update /etc/hosts file if replacing existing cluster
  - [ ] Run deployment tests
  - [ ] Test well known endpoints (AS and RS) conform to customer spring config
  - [ ] Run smoke test
  - [ ] Test consent UI (hybrid flow) allows authorization and has correct branding
  - [ ] Test you can login to Register UI (LBG-only) or Directory UI
  - [ ] Test a domestic single payment consent (if payments is active on cluster)
  - [ ] Export a user from the Data API
  - [ ] Check Swagger has correct branding
- [ ] For Blue/green only: Update load-balancer
  - [ ] Create tfvars for ob-infra-lb
  - [ ] Run ob-infra-lb pipeline
  - [ ] Switch DNS over while retaining Static IP
