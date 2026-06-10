# cwb-proto

Protobuf service definitions for the **CarriedWorld Backbone (CWB)** gRPC mesh, with `buf`-managed codegen. Each pillar exposes gRPC services (and grpc-gateway HTTP/JSON bindings) generated from these `.proto` files.

```
module github.com/CarriedWorldUniverse/cwb-proto   # generated Go under gen/go
```

## Services

| Proto | Package | Services |
|---|---|---|
| `proto/cwb/v1/ledger.proto` | `cwb.v1` | `IssueService`, `ProjectService`, `OrgService`, `AdminService` |
| `proto/cwb/v1/commonplace.proto` | `cwb.v1` | `KnowledgeService` |
| `proto/cwb/v1/common.proto` | `cwb.v1` | shared messages |
| `proto/cwb/cairn/v1/cairn.proto` | `cwb.cairn.v1` | `RepoService`, `PullService`, `OrgService` |
| `proto/cwb/herald/v1/herald.proto` | `cwb.herald.v1` | `AdminService`, `AgentService` |

Generated Go (messages, gRPC stubs, grpc-gateway) is committed under `gen/go/`.

## Tooling

`buf` v2 (`buf.yaml` / `buf.gen.yaml` / `buf.lock`), depending on `buf.build/googleapis/googleapis` for the HTTP-annotation and field-behavior options. Codegen runs three plugins: `protoc-gen-go`, `protoc-gen-go-grpc`, and `protoc-gen-grpc-gateway` (with `allow_delete_body=true` for herald's confirm-by-name `DeleteOrg`).

## Regenerate

```sh
buf lint
buf generate
```

Generated code is checked in; CI (`.github/workflows/buf.yml`) lints, runs `buf generate`, and fails on drift, so regenerate and commit `gen/` whenever a `.proto` changes. The plugin versions CI pins (e.g. `protoc-gen-go@v1.36.11`) are the canonical ones to install locally.
