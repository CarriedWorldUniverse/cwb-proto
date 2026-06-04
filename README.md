# cwb-proto

Shared protobuf/gRPC definitions for the Carried World Builder (CWB) platform mesh — the admin and service RPCs for the herald, cairn, ledger, and commonplace pillars, plus the common identity types they share. These are the wire contracts for the gRPC-over-mTLS mesh that sits behind interchange.

## Layout

- `proto/` — the `.proto` source of truth, organised as `proto/cwb/<package>/v1/`.
- `gen/go/` — the generated Go (message types, gRPC clients/servers, and grpc-gateway handlers). It is **committed** so consumers import it directly without running codegen themselves.

The generated Go module is:

```
github.com/CarriedWorldUniverse/cwb-proto
```

Generated packages live under the `gen/go/cwb/...` import path, e.g. `github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1` and `.../gen/go/cwb/herald/v1`.

## Package map

| Proto file | Package | Services | Pillar |
| --- | --- | --- | --- |
| `proto/cwb/v1/common.proto` | `cwb.v1` | _(types only)_ — canonical identity metadata keys (`cwb-org`, `cwb-subject`, `cwb-kind`, `cwb-scopes`, `cwb-products`, `cwb-responsible-human`) | shared |
| `proto/cwb/v1/ledger.proto` | `cwb.v1` | `IssueService`, `ProjectService`, `OrgService`, `AdminService` | ledger |
| `proto/cwb/v1/commonplace.proto` | `cwb.v1` | `KnowledgeService` | commonplace |
| `proto/cwb/herald/v1/herald.proto` | `cwb.herald.v1` | `AdminService`, `AgentService` | herald |
| `proto/cwb/cairn/v1/cairn.proto` | `cwb.cairn.v1` | `RepoService`, `PullService`, `OrgService` | cairn |

`herald` and `cairn` live in their own packages (`cwb.herald.v1`, `cwb.cairn.v1`) rather than the shared `cwb.v1`, because each defines its own `OrgService`/admin surface that would otherwise clash with ledger's in a single package.

Notes on the pillar surfaces:

- **ledger** — `IssueService` covers the `/api/issues/*` routes (get, update, transition, assign, comment, claim, watchers, links, plus the `my`/`ready`/`search`/`updates` collections); `ProjectService` covers projects; `OrgService` is the tenant-scoped self-purge; `AdminService` covers `/api/admin/*` orgs/members/users.
- **commonplace** — `KnowledgeService` provides `Store`, `Search`, `List`, `Get`, `Update`, `Delete`, and `PurgeOrg`.
- **herald** — `AdminService` is org/identity administration (org, human, agent, product, token management) fronted by interchange with identity-derived authz; `AgentService.GetAgentByFingerprint` is gRPC-only and dialed in-cluster over mTLS (no HTTP annotation). herald's OIDC and agent-bootstrap faces stay on HTTP and are intentionally **not** modelled here.
- **cairn** — `RepoService` and `PullService` are the JSON repo/pull-request API; `OrgService.PurgeOrg` is the cross-pillar org purge. cairn's git wire protocol (Smart-HTTP + SSH) stays on its existing transports and is not part of this proto.

Identity (verified caller org/subject/scopes) flows over gRPC metadata keys defined in `common.proto` — injected by interchange after JWT verification — rather than as request fields.

## Codegen

Codegen uses [buf](https://buf.build). The configuration lives in:

- `buf.yaml` — module path (`proto`), `STANDARD` lint rules, `FILE` breaking-change rules, and the `googleapis` dependency (pinned in `buf.lock`).
- `buf.gen.yaml` — managed mode with `go_package_prefix` set to `github.com/CarriedWorldUniverse/cwb-proto/gen/go`, running `protoc-gen-go`, `protoc-gen-go-grpc`, and `protoc-gen-grpc-gateway` into `gen/go` with `paths=source_relative`.

Regenerate after editing any `.proto`:

```sh
buf lint
buf generate
```

Validate against the published contract before merging:

```sh
buf breaking --against 'https://github.com/CarriedWorldUniverse/cwb-proto.git#branch=main'
```

CI (`.github/workflows/buf.yml`) runs `buf lint` and `buf breaking` on every PR (via `bufbuild/buf-action`, comparing against published `main`), then regenerates `gen/` and fails on any drift (`git diff --exit-code gen/`), and finally builds the generated Go. The codegen plugin versions are pinned in the workflow to match the committed output.

## Consuming the generated Go

Add the module and import the generated packages directly:

```go
import (
	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"
	cairnv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/cairn/v1"
)
```

The CWB pillars (herald, cairn, ledger, commonplace) and their clients depend on this generated Go as the single source of message and gRPC-service definitions — keeping every side of the mesh on one wire contract.

## Where this fits

cwb-proto is the wire contract for the CWB gRPC mesh: pillars serve these services over gRPC-over-mTLS behind interchange, which terminates JWTs and forwards verified identity as the `cwb-*` metadata defined here.
