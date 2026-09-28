# HTTP API

The dispatcher's public API is defined by [`api/openapi.yaml`](../api/openapi.yaml). That OpenAPI document is the authoritative wire contract: routes, request and response shapes, fields, units, defaults, and error responses. A running dispatcher serves the document it was built with at `/openapi.yaml`.

```sh
curl -s https://dispatcher.example/openapi.yaml
curl -s https://dispatcher.example/version
```

## Use the API

- Use [`pkg/client`](client.md) from Go.
- Use `dbl` for shell workflows.
- Generate or write a client from the OpenAPI document for other languages.
- Authenticate protected requests with a session token. See the `securitySchemes` and per-operation requirements in OpenAPI.

## Compatibility

`GET /version` reports three independent values:

| Field | Meaning |
| --- | --- |
| `api_version` | HTTP API compatibility version. |
| `binary_version` and `binary_revision` | Dispatcher build identity. |
| `protocol_version` | Dispatcher/executor control protocol; not for HTTP clients. |

Clients may send `Debuglet-API-Version: major.minor`. Within one API major version, clients must ignore unknown response fields and unknown values in open string fields. Breaking wire changes require a new API major version.

## Errors and health

API failures use `{"code": "…", "message": "…"}`. Programmatic clients should branch on `code`, not the human-readable message.

A `message` contains only fixed text written for that failure or a value from your own request repeated back and cut to at most 64 bytes (with `...` marking the cut and control characters replaced by spaces). It never contains database, runtime or transport diagnostics, and never a credential: no session token, CSRF token, account key, recovery code or payment `auth_key`, whether valid or rejected. The `error` field of a run's state and logs contains the recorded workload error; for results recorded by this version, it is cut to 512 bytes and marked with `...`, with control characters replaced by spaces. Earlier results are returned as stored. Failures inside the dispatcher answer `internal_error` with a fixed message; their cause is written to the dispatcher's log as a Warn entry `request failed` with the route, the status, the code and the underlying error. There is no API route that returns these details: an operator reads them in the daemon log.

Health endpoints are public:

| Endpoint | Meaning |
| --- | --- |
| `/healthz` | Process is serving requests. |
| `/readyz` | Dispatcher can admit new work. |
| `/health` | Expanded readiness observations. |

The OpenAPI document contains the complete status-code and schema reference. Deployment authentication and transport security are covered in the [project Wiki](https://github.com/netsec-ethz/debuglet/wiki).
