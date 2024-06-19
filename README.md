[![CI](https://github.com/projectsveltos/access-manager/actions/workflows/main.yaml/badge.svg)](https://github.com/projectsveltos/access-manager/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectsveltos/access-manager)](https://goreportcard.com/report/github.com/projectsveltos/accesss-manager)
[![Slack](https://img.shields.io/badge/join%20slack-%23projectsveltos-brighteen)](https://join.slack.com/t/projectsveltos/shared_invite/zt-1hraownbr-W8NTs6LTimxLPB8Erj8Q6Q)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](LICENSE)
[![Twitter Follow](https://img.shields.io/twitter/follow/projectsveltos?style=social)](https://twitter.com/projectsveltos)

# Sveltos

<img src="https://raw.githubusercontent.com/projectsveltos/sveltos/main/docs/assets/logo.png" width="200">

Please refere to sveltos [documentation](https://projectsveltos.github.io/sveltos/).

Access manager is a projectsveltos service whose goals are:
1) to generate a kubeconfig using [TokenRequest](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/);
2) process [RoleRequest](https://raw.githubusercontent.com/projectsveltos/libsveltos/main/api/v1beta1/rolerequest_type.go)

RoleRequest are used by platform admin to grant permissions to tenant admins in one or more managed clusters.

AccessRequests are used for sveltos services deployed in the managed clusters that need to access back management cluster.
Any other service can request a kubeconfig by creating an AccessRequest. 
Access manager then:
1. generates kubeconfig;
2. stores in a secret;
3. updates AccessRequest Status with the information on the Secret containing the kubeconfig;
4. continuosly regenerate the token (whose expiration is set to 10 minutes)

## Contributing 

❤️ Your contributions are always welcome! If you want to contribute, have questions, noticed any bug or want to get the latest project news, you can connect with us in the following ways:

1. Open a bug/feature enhancement on github [![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/projectsveltos/sveltos-manager/issues)
2. Chat with us on the Slack in the #projectsveltos channel [![Slack](https://img.shields.io/badge/join%20slack-%23projectsveltos-brighteen)](https://join.slack.com/t/projectsveltos/shared_invite/zt-1hraownbr-W8NTs6LTimxLPB8Erj8Q6Q)
3. [Contact Us](mailto:support@projectsveltos.io)

## License

Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
