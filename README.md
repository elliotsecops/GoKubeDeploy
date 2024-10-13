# GoKubeDeploy: A Minimalist Kubernetes Health Checker in Go

GoKubeDeploy provides a production-ready, minimalist implementation of a Kubernetes health checker in Go. It features a highly efficient and reliable `/healthz` endpoint that returns a JSON status report, ideal for integration with Kubernetes liveness and readiness probes.

## Key Features

- **Secure by Design:**
  - **Automated Security Scanning:** CI/CD pipeline includes Trivy for Docker image vulnerability scanning and static code analysis.
  - **Secure Authentication and Authorization:** JWT-based authentication and authorization.
  - **Robust Error Handling and Centralized Logging:** Improved error handling with detailed logging using Logrus and Fluent Bit for centralized log collection.
  - **Secrets Management:** Kubernetes Secrets for managing sensitive credentials.
  - **Network Security:** Network Policies to restrict pod-to-pod communication.
  - **Zero-Downtime Deployments:** Readiness probes for seamless updates.
  - **Dependency Management:** Go Modules for secure and reproducible builds.

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

Check the pod status to confirm successful deployment:

```bash
kubectl get pods
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

### JWT Example

To generate a JWT for authentication, use the following Go code:

```go
import (
    "github.com/dgrijalva/jwt-go"
    "time"
)

var jwtKey = []byte("your_secret_key")

type Claims struct {
    Username string `json:"username"`
    Role     string `json:"role"`
    jwt.StandardClaims
}

func generateJWT(username, role string) (string, error) {
    expirationTime := time.Now().Add(5 * time.Minute)
    claims := &Claims{
        Username: username,
        Role:     role,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(jwtKey)
}
```

To verify a JWT, use the following code:

```go
func verifyJWT(tokenString string) (*Claims, error) {
    claims := &Claims{}
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if err != nil {
        return nil, err
    }
    if !token.Valid {
        return nil, fmt.Errorf("invalid token")
    }
    return claims, nil
}
```

## Project Structure

- `healthcheck.go`: Go application source code, including the health check logic and HTTP server.
- `Dockerfile`: Docker build instructions.
- `kubernetes/deployment.yaml`: Kubernetes deployment configuration, including resource limits and liveness/readiness probes.
- `kubernetes/networkpolicy.yaml`: Network policies to restrict pod-to-pod communication.
- `kubernetes/secret.yaml`: Kubernetes Secrets for managing sensitive credentials.
- `fluent-bit.conf`: Configuration for Fluent Bit sidecar for centralized logging.
- `.github/workflows/ci-cd.yaml`: GitHub Actions workflow for CI/CD pipeline.

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

## Security Considerations

### Secure Coding Practices

- **Input Validation:** Use libraries like `validator.v10` for robust input validation. Validate all inputs to prevent common vulnerabilities such as SQL injection and XSS.
- **Error Handling:** Implement secure error handling practices. Log errors with sufficient detail for diagnosis but avoid logging sensitive information.
- **Dependency Management:** Use `go mod tidy` to clean up unused dependencies and `govulncheck` to scan for vulnerabilities in dependencies.

### Container Image Security

- **Vulnerability Scanning:** Regularly scan Docker images using tools like Trivy to identify and remediate vulnerabilities.
- **Minimal Base Images:** Use minimal base images (e.g., Alpine) to reduce the attack surface.

### Network Security

- **Network Policies:** Implement Kubernetes Network Policies to restrict communication between pods and enhance security.

### Secrets Management

- **Kubernetes Secrets:** Store sensitive information in Kubernetes Secrets and inject them as environment variables. Avoid hardcoding secrets in the code or configuration files.

### Logging and Monitoring

- **Centralized Logging:** Use Fluent Bit for centralized logging. Ensure logs are sent to a secure, centralized logging system like Elasticsearch or a cloud logging service.
- **Monitoring:** Integrate with monitoring tools like Prometheus and Grafana for comprehensive health monitoring and alerting.

