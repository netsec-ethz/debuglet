# Debuglet Software

## Prerequisite

- SCION endhost stack
- Docker & Docker Compose
- OpenSSL (for generating test certificates locally)
- Go (optional, for local standalone development)

## Deployment

The Debuglet ecosystem (Dispatcher and Executor) is containerized via Docker for easy setup and operation.

1. **Bootstrap Certificates and Configurations**  
   Run the following command to generate the required `configs/` structure mapped as Docker volumes, along with the necessary TLS certificates.
   ```bash
   make generate-certs
   ```
   *You can freely modify the configuration templates in `configs/executor/executor.toml` and `configs/dispatcher/dispatcher.toml` before starting the services.*

2. **Start the Services**  
   You can choose to start both components at once or just one selectively:
   
   To start both:
   ```bash
   make docker-up-all
   ```
   
   To start only the executor or dispatcher:
   ```bash
   make docker-up-executor
   # or
   make docker-up-dispatcher
   ```

3. **Check Logs**  
   To view the logs from both the dispatcher and the executor, run:
   ```bash
   docker compose logs -f
   ```

4. **Tear down**  
   To stop and remove the containers, run:
   ```bash
   make docker-down
   ```

## Local Development (Optional)

If you need to build the Go binaries locally outside of Docker:
```bash
make deps
make build
```