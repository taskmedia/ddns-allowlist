# Kubernetes examples

Here you will find an example how to use (or test) the DDNS allowlist plugin with Traefik in your cluster.

## Installation

This installation requires [minikube](https://minikube.sigs.k8s.io/) to be installed and started.
Also you need [Helm](https://helm.sh) to be installed as well.

The installation will automatically create a minikube tunnel and mount the repository directory into minikube.
Traefik will be available via port `8080` and `9000`.

1. Start your minikube Kubernetes cluster<br/>
1. Install and test via script<br/>
   ```bash
   tests/k8s/install.bash
   ```
1. Access the traefik endpoint to view your dashboard<br/>
   http://localhost:9000/dashboard/#/http/routers
1. Try to access the traefik endpoints
   ```bash
   # endpoint without middleware
   curl -v http://whoami.localhost:8080
   # endpoint with middleware but allowed host
   curl -v http://allow.whoami.localhost:8080
    # endpoint with middleware but denied host
   curl -v http://deny.whoami.localhost:8080
   ```
1. Uninstall via script
   ```bash
   tests/k8s/uninstall.bash
   ```

### Endpoints

- http://whoami.localhost:8080
- http://allow.whoami.localhost:8080
- http://deny.whoami.localhost:8080
- http://localhost:9000/dashboard/#/http/routers

## Resources

### Helm

The resources how to deploy Traefik with Helm can be found in the [traefik-values.yml](./traefik-values.yml) file.
Take note that this configuration uses the local filesystem to mount the repository inside the pod.
This will allow to test the development version of the plugin.

### Kubernetes resources

If you want to have a look how a [middleware or IngressRoute](./resources/allow.yml) can be configured take a look about the K8s resources used.
You will find them in the [resources](./resources) directory.

In [allow.yml](./resources/allow.yml) you will find the example configuration where `localhost` access is allowed.
The [deny.yml](./resources/deny.yml) configuration only allows an access from Google`s DNS servers - so no access will be granted.
Within the [service.yml](./resources/service.yml) you will find the service configuration for the whoami example service.
