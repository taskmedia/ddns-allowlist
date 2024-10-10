#!/bin/bash

# get directory of this script
DIR_TESTS_K8s="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Function to check if a namespace exists, if not create it
ensure_namespace() {
  local ns=$1
  if ! kubectl get namespace "$ns" > /dev/null 2>&1; then
      kubectl create namespace "$ns"
  fi
}

minikube_tunnel_start() {
  nohup minikube tunnel --bind-address="127.0.0.1" &
}
minikube_mount_start() {
  nohup minikube mount "${DIR_TESTS_K8s}/../..:/ddnswl" &
}

# exit if context is not minikube
kubectl config current-context | grep minikube || { echo "Context is not minikube"; exit 1; }

ensure_namespace ingress
kubectl config set-context --current --namespace=ingress

# ensure ip can be assigned by minikube tunnel
minikube_tunnel_start
# ensure repo can be assigned by minikube via volume
minikube_mount_start

# check if traefik repo already exists if not add it
helm repo list | grep traefik || helm repo add traefik https://helm.traefik.io/traefik

# install default traefik with Helm
helm upgrade --install traefik \
  traefik/traefik \
  --namespace ingress \
  --values "${DIR_TESTS_K8s}/traefik-values.yml" \
  --wait

# deploy demo application
ensure_namespace whoami
time
kubectl apply -f "${DIR_TESTS_K8s}/resources/service.yml" --namespace whoami
sleep 5
time
kubectl apply -f "${DIR_TESTS_K8s}/resources/allow.yml" --namespace whoami
kubectl apply -f "${DIR_TESTS_K8s}/resources/deny.yml" --namespace whoami

IP_TRAEFIK=$(kubectl get pods -l app.kubernetes.io/name=traefik -o jsonpath='{.items[0].status.podIP}')
# get first IP address
IP_TUNNEL="${IP_TRAEFIK%.*}.1"

# create a k8s patch to update the middleware to add minikube tunneling IP to whitelist
kubectl patch middlewares.traefik.io ddnsallowlist-allow --namespace whoami --type merge -p "{
    \"spec\": {
        \"plugin\": {
            \"ddns-allowlist\": {
                \"sourceRangeIps\": [
                    \"${IP_TUNNEL}\"
                ]
            }
        }
    }
}"

echo "-------------------------------------"
kubectl get pod --all-namespaces
sleep 30
kubectl get pod --all-namespaces
echo "-------------------------------------"
kubectl get svc --all-namespaces
echo "-------------------------------------"
curl http://whoami.localhost:8080 -v || true
echo "-------------------------------------"
curl http://allow.whoami.localhost:8080 -v || true
echo "-------------------------------------"
curl http://deny.whoami.localhost:8080 -v || true
echo "-------------------------------------"
kubectl logs pod/$(kubectl get pods -l app.kubernetes.io/name=traefik -o jsonpath='{.items[0].metadata.name}')
echo "-------------------------------------"
curl http://localhost:9000/api/http/routers | jq
echo "-------------------------------------"
curl http://localhost:9000/api/http/middlewares | jq
echo "-------------------------------------"
curl http://localhost:9000/api/http/services | jq
echo "-------------------------------------"

# check http response code
curl -s -o /dev/null -w "%{http_code}" http://allow.whoami.localhost:8080 | grep 200 || { echo "Failed to get 200 response code"; exit 1; }
curl -s -o /dev/null -w "%{http_code}" http://deny.whoami.localhost:8080 | grep 403 || { echo "Failed to get 403 response code"; exit 1; }
