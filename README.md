# Validate kubernetes manifests
[![release](https://github.com/doodlescheduling/yakmv/actions/workflows/release.yaml/badge.svg)](https://github.com/doodlescheduling/yakmv/actions/workflows/release.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/doodlescheduling/yakmv)](https://goreportcard.com/report/github.com/doodlescheduling/yakmv)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/DoodleScheduling/yakmv/badge)](https://api.securityscorecards.dev/projects/github.com/DoodleScheduling/yakmv)
[![Coverage Status](https://coveralls.io/repos/github/DoodleScheduling/yakmv/badge.svg?branch=master)](https://coveralls.io/github/DoodleScheduling/yakmv?branch=master)

Validate kubernetes manifests (before they are applied to any cluster).
This app was written as replacement for [kubeconform](https://github.com/yannh/kubeconform) and similar validation tools.
The main problem with these tools are that they validate the resources with json schemas. 
The advantage is that it is very fast but missing out on various validations including:

* any additional validation done on the api server as code
* crds which contain CEL validations

In addition to that any crds must be converted to json schemas beforehand.

What if there is a tool which can take a bunch of manifests including crds and validate all of them just like applying them
to a real cluster? Well this app does exactly that.
It actually does apply all the manifests to a temporary real kube-apiserver behind the scenes.

## Example usage

```
curl -L https://github.com/fluxcd/flux2/releases/download/v2.2.3/install.yaml | yakmv --kube-version=1.27.0 --table
```

## Installation

### Brew
```
brew tap doodlescheduling/yakmv
brew install yakmv
```

### Docker
```
docker pull ghcr.io/doodlescheduling/yakmv:v0
```

## Arguments

| Short | Flag  | Env | Default | Description |
| ------------- | ------------- | ------------- | ------------- | ------------- |
| `-f` | `--file`  | `FILE` | `/dev/stdin` | Path to input |
| `` | `--fail-fast`  | `FAIL_FAST` | `false` | Exit early if an error occured |
| `` | `--allow-failure`  | `ALLOW_FAILURE` | `false` | Do not exit > 0 if an error occured |
| `` | `--api-server-registry`  | `API_SERVER_REGISTRY` | `registry.k8s.io/kube-apiserver` | OCI registry for pulling the kube-apiserver image |
| `` | `--etcd-registry`  | `ETCD_REGISTRY` | `quay.io/coreos/etcd` | OCI registry for pulling the etcd image |
| `` | `--exclude-valid`  | `EXCLUDE_VALID` | `` | Only included invalid manifests in the output |
| `` | `--kube-version`  | `KUBE_VERSION` | `1.28.0` | Kubernetes version, for instead 1.27.0. If not set the latest stable one is used |
| `` | `--etcd-version`  | `ETCD_VERSION` | `3.5.11` | The version for etcd |
| `-e` | `--log-encoding`  | `LOG_ENCODING` | `json` | Define the log format (default is json) [json,console] |
| `-l` | `--log-level`  | `LOG_LEVEL` | `fatal` | Define the log level (default is warning) [debug,info,warn,error] |
| `` | `--namespace`  | `` | `NAMESPACE` | Default namespace to apply to resources without a namespace |
| `` | `--skip-auto-namespace`  | `SKIP_AUTO_NAMESPACE` | `false` | Do not create a namespace if it does not exists yet while validating a resource |
| `` | `--table`  | `TABLE` | `false` |  |
| `` | `--api-server-flags`  | `API_SERVER_FLAGS` | `--api-server-flags="--disable-admission-plugins=MutatingAdmissionWebhook,ValidatingAdmissionPolicy,ValidatingAdmissionWebhook"` | Set additional kube-apiserver flags. |


## Github Action

This app works also great on CI, in fact this was the original reason why it was created.

### Example usage

```yaml
name: yakmv
on:
- pull_request

jobs:
  build:
    strategy:
      matrix:
        cluster: [staging, production]

    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@24cb9080177205b6e8c946b17badbe402adc938f # v3.4.0
    - uses: docker://ghcr.io/doodlescheduling/yakmv:v0
      env:
        PATHS: ./${{ matrix.cluster }}
        OUTPUT: /dev/null
```