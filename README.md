[![CI](https://github.com/projectsveltos/access-manager/actions/workflows/main.yaml/badge.svg)](https://github.com/projectsveltos/access-manager/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectsveltos/access-manager)](https://goreportcard.com/report/github.com/projectsveltos/accesss-manager)
[![Slack](https://img.shields.io/badge/join%20slack-%23projectsveltos-brighteen)](https://join.slack.com/t/projectsveltos/shared_invite/zt-1hraownbr-W8NTs6LTimxLPB8Erj8Q6Q)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](LICENSE)
[![Twitter Follow](https://img.shields.io/twitter/follow/projectsveltos?style=social)](https://twitter.com/projectsveltos)

# Sveltos

<img src="https://raw.githubusercontent.com/projectsveltos/access-manager/dev/logos/logo.png" width="200">

Access manager is a projectsveltos service whose only goal is to generate a kubeconfig using [TokenRequest](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/).

Any other service can request a kubeconfig by creating an AccessRequest.
Access manager then:
1. generates kubeconfig;
2. stores in a secret;
3. updates AccessRequest Status with the information on the Secret containing the kubeconfig;
4. continuosly regenerate the token (whose expiration is set to 10 minutes)
