#!/bin/bash

minikube_stop_all() {
  pgrep -f minikube | xargs kill
}

# install default traefik with Helm
helm uninstall traefik --namespace ingress

# stop all minikube commands (tunnel, volume)
minikube_stop_all
