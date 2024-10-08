# Kubernetes examples

Here you will find an example how to use (or test) the DDNS allowlist plugin with Traefik in your cluster.

1. Install the Helm chart of Traefik<br/>
   ```bash
   helm upgrade --install traefik traefik/traefik --values ./traefik-values.yml
   ```
2. Apply the k8s resources containing deployment, service, middleware and IngressRoutes.<br/>
   ```bash
   kubectl apply -f ./resources
   ```
3. Port-forward the web and traefik endpoint.<br/>
   ```bash
   # web endpoint
   kubectl port-forward $(kubectl get pods -l app.kubernetes.io/name=traefik -o jsonpath='{.items[0].metadata.name}') 8080:8000
   # traefik endpoint
   kubectl port-forward $(kubectl get pods -l app.kubernetes.io/name=traefik -o jsonpath='{.items[0].metadata.name}') 9090:9000
   ```
4. Access the traefik endpoint to view your dashboard.
   `http://localhost:9090/dashboard/#/http/routers`
5. Try to access the traefik endpoints.
   ```bash
   # endpoint without middleware
   curl -v http://whoami.localhost:8080
   # endpoint with middleware but allowed host
   curl -v http://allow.whoami.localhost:8080
    # endpoint with middleware but denied host
   curl -v http://deny.whoami.localhost:8080
   ```
