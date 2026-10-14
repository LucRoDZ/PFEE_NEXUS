# NEXUS — proof of concept

Proof of concept for the NEXUS study report (PFEE 2026, EPITA). It demonstrates the three mechanisms the report claims:

1. **HDG only ever sees ciphertext.** Files are de-identified and encrypted at the hospital, and the keys stay at the hospital.
2. **A revoked consent cuts access at once.** Erasing the patient's key makes every copy unreadable, backups included (crypto-shredding).
3. **Any edit to the audit log is detected,** including a full rewrite of the chain by HDG's own administrator.

`make demo` runs them and prints 15 pass/fail checks (G1, G2, G3 and G5).

## Architecture

```
 HOSPITAL (keys live here)                         HDG PRIVATE CLOUD (ciphertext only)
 ┌──────────────────────────────┐                  ┌──────────────────────────────────┐
 │ gateway: de-identify (DICOM),│  ciphertext +    │ data API ──► Garage (S3)          │
 │ encrypt AES-256-GCM          │  wrapped key ──► │                                  │
 │                              │                  │ consent service (signed grants)  │
 │ key broker: one KEK per      │ ◄── grant check ─┤                                  │
 │ patient, releases a data key │                  │ audit service (hash chain)       │
 │ only for a valid signed grant│ ── every decision ──►                                │
 │                              │                  └──────────────────────────────────┘
 │ anchors: copies of the audit │ ◄── head hash every 10 min
 │ chain head, out of HDG reach │
 └──────────────────────────────┘
        ▲ signed grants / revocations / erasure
 ┌──────┴───────────────────────┐
 │ patient agent + portal on the│
 │ patient's device (Ed25519    │
 │ key never leaves it)         │
 └──────────────────────────────┘
```

| Component | Code | Runs at | Role |
|---|---|---|---|
| Gateway | `nexus/hospital/gateway.py`, `deid.py` | hospital | DICOM PS3.15 Basic Profile subset, pseudonym (mapping kept locally), per-object data key, AES-256-GCM |
| Key broker | `nexus/hospital/keybroker.py` | hospital | Per-patient KEK sealed by a master key (HSM in the target). Releases a data key only if the grant is signed by the patient, names the requester, is unexpired and unrevoked, and the decision was logged |
| Anchors | `nexus/hospital/anchor.py` | hospital | Copies the audit chain head; detects any later rewrite |
| Data API | `nexus/hdg/data_api.py` | HDG | Stores and serves ciphertext + wrapped keys on S3 (Garage) |
| Consent | `nexus/hdg/consent.py` | HDG | Stores patient-signed grants and revocations; patient access log (EHDS art. 9) |
| Audit | `nexus/hdg/audit.py`, `chain.py` | HDG | Append-only SHA-256 hash chain |
| Patient portal | `nexus/patient/agent.py` | patient device | Signs grants, revocations, erasure; shows who accessed the data |
| Researcher | `nexus/researcher/client.py`, `ai_job.py` | AI zone | Fetches ciphertext, requests keys; AI job outputs aggregates only |

Design rules enforced in code:

- **HDG cannot forge a grant.** The broker checks each grant against its own copy of the patient's public key.
- **HDG cannot hide a revocation.** The patient's device sends it to both the consent service and the broker.
- **No log, no key.** If the audit service cannot record a release, the key is not released.

## All the measurements for the report, in one command

```bash
make measure        # about 3 minutes: demo (15 checks), G5, load tests, red team
make g4             # needs Docker: G4, nothing on the HDG network reaches the internet
make measure-all    # both of the above
```

Results land in `measurements/<date-time>/`. `SUMMARY.md` there holds the text for every `[MEASURE]` cell of the report (§6.1, §6.2, §7, §8), ready to paste. On the k3s cluster, G4 is `kubectl -n hdg exec deploy/data-api -- python demo/egress_probe.py`.

## Quick start (local, about 2 minutes)

Requires Python 3.11+.

```bash
make install
make demo          # starts everything, runs scenes 1-3, prints 12 checks
make down
```

If `make up` reports a busy port, another program on your machine uses it: stop it, or move the S3 emulator with `NEXUS_S3_PORT=9070 make up` (use the same variable for the next `make` commands). `make up` always stops processes left over from an earlier run first.

Step by step, as in the video:

```bash
make up            # S3 emulator + HDG services + hospital services
make setup         # synthetic X-rays with a fake identity, patient enrollment, first grant
make portal        # patient portal on http://127.0.0.1:8301
make scene1        # gateway upload, admin reads raw storage, HDG asks for a key and is refused
make scene2        # researcher reads, patient revokes, every later request refused; erasure
make scene3        # patient access log, then two tampering attacks on the audit log
```

To revoke by hand from the portal while watching the effect live:

```bash
python -m nexus.researcher.client watch OBJECT_ID GRANT_ID --interval 0.1
```

`OBJECT_ID` and `GRANT_ID` are in `var/demo_state.json` after `make setup` and `make scene1`. Click **Revoke** in the portal: the watcher switches from ALLOWED to DENIED.

Results for the report are written to `var/results.json` (demo) and `var/loadtest-*.json` (load tests).

## Load tests

```bash
make up && make setup
make load
```

| Mode | What it measures |
|---|---|
| `upload` | de-identify + encrypt + wrap + store, per image |
| `read` | ciphertext download only (baseline) |
| `full` | ciphertext + key request (signature, consent, audit) + decryption: the cost of the protections is `full − read` |
| `revoke` | revocation in the middle of a full load: requests allowed after revocation (target 0) and delay |

Each result also lists `errors_by_cause` and, for `full` and `revoke`, every outcome with its reason, so a refusal caused by load (fail-closed) is never confused with a refusal caused by revocation.

Run them on the k3s cluster for the report figures. Local runs go through an S3 emulator and a single worker per service, so they are slower than the real deployment.

## Deployment on k3s (3 bare-metal nodes)

Two nodes play HDG's cloud and one node plays the hospital site. Hospital pods are pinned to the hospital node.

```bash
# 1. k3s with Cilium instead of flannel (enables network policies + WireGuard between nodes)
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy" sh -
helm repo add cilium https://helm.cilium.io
helm install cilium cilium/cilium -n kube-system \
  --set encryption.enabled=true --set encryption.type=wireguard

# 2. label the nodes
kubectl label node node1 node2 nexus/site=hdg
kubectl label node node3 nexus/site=hospital

# 3. Garage (3 replicas, one per HDG node) with its official Helm chart, in namespace "garage"
#    https://garagehq.deuxfleurs.fr/documentation/cookbook/kubernetes/
#    then: garage key create nexus; garage bucket create nexus-objects; garage bucket allow ...

# 4. image, secrets, manifests
make image && docker save nexus-poc:0.1 | sudo k3s ctr images import -
kubectl apply -f deploy/k8s/00-namespaces.yaml
cp deploy/k8s/05-secrets.example.yaml deploy/k8s/05-secrets.yaml   # fill the Garage key, then:
kubectl apply -f deploy/k8s/05-secrets.yaml
kubectl apply -f deploy/k8s/10-hdg.yaml -f deploy/k8s/20-hospital.yaml
kubectl apply -f deploy/k8s/30-network-policies.yaml -f deploy/k8s/40-ingress.yaml
```

Network policies deny everything by default, in and out. Only the flows in the architecture diagram are allowed, and no pod can reach the internet (promise 4).

A docker compose variant (`deploy/docker-compose.yml`, with `deploy/garage-init.sh`) runs the same split on one machine.

## What is real and what is simulated

| Item | PoC | Target architecture |
|---|---|---|
| Encryption, key wrapping, signatures, hash chain | real (AES-256-GCM, Ed25519, SHA-256) | same |
| S3 storage | Garage on k3s; S3 emulator (moto) for local runs | Garage, replication 3 |
| Identities | static bearer tokens | Keycloak (OIDC, MFA), Pro Santé Connect for professionals |
| Hospital master key | file on the hospital node | HSM at the hospital |
| AI zone | isolated namespace, aggregates only | confidential VMs (AMD SEV-SNP / Intel TDX), key release after attestation |
| Patient signing key | file on the patient device | device secure enclave / passkey |
| De-identification | DICOM Basic Profile subset; burned-in files quarantined | full profile + pixel cleaning |

## Tested

- `make demo` and `make test` (end to end, 15 checks), `make redteam` and `make measure` pass locally with the S3 emulator.
- All four load-test modes run locally.
- `make g4`, the Dockerfile, docker compose file and k3s manifests are written but **not yet run** here (no Docker registry access): run them on your machine.

No real patient data is used: `demo/make_sample_dicom.py` generates synthetic chest X-rays with a fake identity.
