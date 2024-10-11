# GoKubeDeploy

GoKubeDeploy is a minimalist project demonstrating simple Go application deployment on Kubernetes. It features a health checker (`/healthz`) returning a JSON status report.  This project is ideal for learning the basics of Go, Docker, and Kubernetes deployments.

## Features

* Minimalist design: Only essential files and configurations.
* Health check endpoint (`/healthz`): Returns a JSON status.
* Dockerized application: Easy to build and deploy.
* Kubernetes deployment:  Includes replicas, resource limits, liveness, and readiness probes.
* Clear and concise documentation.

## Requirements

* Go (1.16 or later)
* Docker
* Kubectl
* Minikube (or a Kubernetes cluster)
* Docker Hub account (or other container registry)


## Getting Started
1. **Build the Docker image:** `docker build -t your-docker-username/gokubedeploy:latest .` (replace with your Docker Hub username)
2. **Push the image to Docker Hub:** `docker push your-docker-username/gokubedeploy:latest`
3. **Deploy to Kubernetes:** `kubectl apply -f kubernetes/deployment.yaml`
4. **Access the service:** `kubectl get service gokubedeploy-service` (This will show the external IP or hostname if you're using a LoadBalancer service type).

## Usage

Access the health check endpoint to verify application status:

```bash
curl <EXTERNAL-IP>/healthz 
# or
curl <EXTERNAL-NAME>/healthz
```

Project Structure

`healthcheck.go`: Go application source code.

`Dockerfile`: Docker build instructions.

`kubernetes/deployment.yaml`: Kubernetes deployment configuration.

Contributing

Contributions are welcome! Please open an issue or submit a pull request.

License

`MIT License`
