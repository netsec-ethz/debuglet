# Debuglet Software

## Prerequisite

- Go (for local standalone development and compiling WASM)
- SCION endhost stack (optional, for using SCION-specific functionality)
- Docker & Docker Compose (optional)
- OpenSSL (optional, for generating new test certificates locally)

## Local Development

[mise](https://mise.jdx.dev/) is given as a helpful tool for managing the correct language versions for local development.

The `Makefile` includes helper-targets to run certain _longer_ commands:

#### Start the dispatcher

```bash
make dispatcher # or make d
```

#### Start a executor

```bash
make executor # or make e
```

#### Generate a WASM binary

```bash
make wasm SAMPLE_DIR=local/wasm-samples/helloworld
# or
make wasm SAMPLE_DIR=local/wasm-samples/send_tcp
```

#### Build new proto files

```bash
make proto
```

### SCION

SCION is a soft-dependency for measurements. If a measurement doesn't try to call any SCION-specific functions, you can simply let the executor time-out when it tries to establish a SCION connection.

### Submitting measurements

Use the debuglet-dashboard to submit measurements.

---

## Deployment

The Debuglet ecosystem (Dispatcher and Executor) is containerized via Docker for easy setup and operation.

1. **Bootstrap Certificates and Configurations**  
   Run the following command to generate the required `configs/` structure mapped as Docker volumes, along with the necessary TLS certificates.

   ```bash
   make generate-certs
   ```

   _You can freely modify the configuration templates in `configs/executor/executor.toml` and `configs/dispatcher/dispatcher.toml` before starting the services._

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

## Flow

```mermaid
sequenceDiagram
    participant Client
    participant Dispatcher
    participant Executor
    participant SCION

    Executor->>Dispatcher: [ControlMessage] Hello
    rect rgba(255, 255, 0, 0.3)
    Executor->>Dispatcher: [ControlMessage] Resources (set bw capacity)
    end
    Executor->>Dispatcher: [ControlMessage] Heartbeat (repeats /60s)

    Client->>Dispatcher: createMeasurement <br/> (POST http /api/measurements)
    activate Dispatcher

    Dispatcher->>Executor: DispatchTask() <br/> [ControlMessage]: Assignment
    activate Executor
    Dispatcher->>Client: measurementId
    deactivate Dispatcher
    Client->>Dispatcher: connectWebsocket <br/> (ws /ws-api/measurements/${measurementId}/start)

    Executor->>Executor: create debuglet <br/> (initialize new wasmer instance)
    Executor->>Executor: Init() -> startServers()
    Executor->>SCION: Connect()
    SCION->>Executor: IA, IP
    Executor->>Dispatcher: [SessionMessage] DebugletReady
    deactivate Executor


    Client->>Dispatcher: ws:start
    activate Dispatcher

    rect rgba(255, 255, 0, 0.3)
    Dispatcher->>Dispatcher: CheckPolicy() & RegisterPolicy()

    Dispatcher->>Executor: Update1(Assignment, Destination)
    Dispatcher-->>Executor: Update2(Assignment, Destination)
    Dispatcher-->>Executor: Update3(Assignment, Destination)
    Executor->>Dispatcher: ack1
    Executor-->>Dispatcher: ack2
    Executor-->>Dispatcher: ack3
    end

    Dispatcher->>Dispatcher: measurement.Start()

    Dispatcher->>Executor: DebugletSession1.Start() <br/> [SessionMessage]: START_EXECUTION
    activate Executor
    Dispatcher-->>Executor: DebugletSession2.Start() <br/> [SessionMessage]: START_EXECUTION
    Dispatcher-->>Executor: DebugletSession3.Start() <br/> [SessionMessage]: START_EXECUTION

    rect rgba(255, 255, 0, 0.3)
    Executor->>Executor: RegisterAssignment1()
    Executor->>Executor: runDebuglet1()
    Executor->>Executor: RemoveAssignment1()

    Executor-->>Executor: Register, Run, Remove 2()
    Executor-->>Executor: Register, Run, Remove 3()
    end

    Executor-->>Dispatcher: [SessionMessage] Stdout1(Stdout)
    Executor-->>Dispatcher: [SessionMessage] Stdout2(Stdout)
    Executor-->>Dispatcher: [SessionMessage] Stdout3(Stdout)

    Executor->>Dispatcher: [SessionMessage] DebugletExit(exitCode, result)
    deactivate Executor

    rect rgba(255, 255, 0, 0.3)
    Dispatcher->>Dispatcher: cleanup debuglet/assignment
    end

    Dispatcher->>Client: result
    deactivate Dispatcher
```
