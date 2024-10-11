# GoKubeDeploy: A Minimalist Kubernetes Health Checker in Go

GoKubeDeploy provides a production-ready, minimalist implementation of a Kubernetes health checker in Go. It features a highly efficient and reliable `healthz` endpoint that returns a JSON status report, ideal for integration with Kubernetes liveness and readiness probes.

## Key Features

- **Minimalist Design:** The single-file Go application and concise deployment manifest minimize complexity and deployment time, ideal for microservices architectures and CI/CD pipelines.
- **Production-Ready:** Includes robust error handling, clear logging, and a JSON-formatted health status report suitable for automated monitoring systems.
- **Kubernetes Best Practices:** Implements liveness and readiness probes to ensure high availability and seamless integration with Kubernetes lifecycle management.
- **Dockerized Application:** Packaged as a lightweight Docker image for easy distribution and deployment.

## Getting Started

### 1. Clone the Repository

Clone the repository to your local machine:

```bash
git clone https://github.com/elliotsecops/GoKubeDeploy.git
cd GoKubeDeploy
```

### 2. Build the Docker Image

Build the Docker image using the provided Dockerfile. The `.` specifies the current directory as the build context:

```bash
docker build -t elliotsecops/gokubedeploy:latest .
```

### 3. Push the Image to Docker Hub

Push the Docker image to Docker Hub:

```bash
docker push elliotsecops/gokubedeploy:latest
```

### 4. Deploy to Kubernetes

Deploy the application to your Kubernetes cluster using the provided deployment manifest. If the deployment already exists, you can use `kubectl apply --force` (with caution) or `kubectl rollout restart deployment gokubedeploy`:

```bash
kubectl apply -f kubernetes/deployment.yaml
```

### 5. Access the Service

If you're using Minikube, you can get the service URL with:

```bash
minikube service gokubedeploy-service --url
```

Otherwise, use:

```bash
kubectl get service gokubedeploy-service
```

Ensure you have a LoadBalancer service type to obtain an external IP. If not, configure a reverse proxy or an ingress controller.

## Usage

The health check endpoint (`/healthz`) returns a JSON response indicating the status of the application. For example:

```bash
curl <SERVICE-URL>/healthz
```

Response:

```json
{
  "status": "OK",
  "message": "" // Optional message in case of errors
}
```

Example with a possible failure:

```json
{
  "status": "ERROR",
  "message": "Database connection failed"
}
```

## Project Structure

- `healthcheck.go`: Go application source code, including the health check logic and HTTP server.
- `Dockerfile`: Docker build instructions.
- `kubernetes/deployment.yaml`: Kubernetes deployment configuration, including resource limits and liveness/readiness probes.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

### Additional Notes

- **Docker Hub Repository:** You can find the Docker image for this project on Docker Hub:

  [elliotsecops/gokubedeploy](https://hub.docker.com/repository/docker/elliotsecops/gokubedeploy)

- **Kubernetes Deployment:** The `deployment.yaml` file configures the application deployment, including replicas, resource limits, and liveness and readiness probes to ensure high availability and proper lifecycle management.

- **Health Check Endpoint:** The `/healthz` endpoint returns a JSON response indicating the status of the application. This is useful for monitoring and ensuring that the application is running correctly.

- **Testing:** The project includes unit tests. Run them using:

  ```bash
  go test ./...
  ```

- **Monitoring:** Integrate with monitoring tools like Prometheus and Grafana for comprehensive health monitoring.

- **Scalability:** The application is designed to scale horizontally. Adjust the number of replicas in the `deployment.yaml` file to meet your needs.

- **Configuration:** Customize the application behavior using environment variables. Refer to the `healthcheck.go` file for available options.

- **Simulate Failure:** Use the `SIMULAR_FALLO` environment variable to simulate a failure. To simulate a failure, run:

  ```bash
  kubectl set env deployment/gokubedeploy SIMULAR_FALLO=true
  ```

  To revert the simulation, run:

  ```bash
  kubectl set env deployment/gokubedeploy SIMULAR_FALLO=false
  ```

- **Architecture Diagram:**

  ```
  +-------------------+       +-------------------+       +-------------------+
  |                   |       |                   |       |                   |
  |   Go Application  |       |   Docker Image    |       |   Kubernetes      |
  |                   |       |                   |       |                   |
  +--------+----------+       +--------+----------+       +--------+----------+
           |                           |                           |
           |                           |                           |
           v                           v                           v
  +-------------------+       +-------------------+       +-------------------+
  |                   |       |                   |       |                   |
  |   Health Check    |       |   Container       |       |   Deployment      |
  |   Endpoint        |       |   Runtime         |       |   Configuration   |
  |                   |       |                   |       |                   |
  +-------------------+       +-------------------+       +-------------------+
  ```

  This diagram illustrates the flow from the Go application, containerized with Docker, to its deployment and monitoring within a Kubernetes cluster, showcasing the core functionality of GoKubeDeploy and its integration with Kubernetes.

## Alternatives

This section lists some alternative libraries and tools that offer similar functionalities.

### Health Check Libraries

- **gopsutil:** A Go library for retrieving system and process information, useful for more extensive health checks.
- **go-health:** A library for implementing health checks in Go applications, providing more advanced features.

### Monitoring Tools

- **Prometheus:** A popular open-source monitoring and alerting system.
- **Grafana:** A powerful open-source platform for data visualization and analysis.
