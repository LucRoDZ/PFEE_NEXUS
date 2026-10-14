# NEXUS measurements, 2026-10-13 06:50

Checks: **15 of 15 passed**.

## §6.1 results table

| Guarantee | Result | Verdict |
|---|---|---|
| G1 | Entropy 8.000 bits/byte on all 3 objects (8 = random); readable markers: none. HDG's key request refused ("grant not found (404)") and logged in the patient's history. No key file on HDG's side. | **Held** for storage, transit and backups; **partial** in the AI zone until a TEE |
| G2 | 6 keys released before, 0 after (10 requests). Revocation recorded at the hospital and at HDG in 94 ms; first refusal 188 ms after the click. After erasure, backup copy plus new grant refused: "patient key destroyed (crypto-shredded)". | **Held** |
| G3 | Edit detected at the exact entry (#5). After the full rewrite, HDG's own check passed; the hospital's anchors caught it (first mismatch at #10, the first anchor taken after the deleted entry). | **Held** |
| G4 | From a container on the HDG network: HTTPS blocked (ConnectError); direct TCP to a public IP blocked (OSError); DNS blocked (gaierror). | **Held** |
| G5 | 3 images processed: none of the 6 identity fields (name, patient ID, birth date, hospital, referring physician, accession number) found in the decrypted inputs or in the output. After the patient withdrew consent, the next run used 0 images and excluded 3. Burned-in file quarantined at the source. | **Held** for header identifiers; pixel content is handled by quarantine only |

## §6.2 load-test table

| Mode | p95 latency (ms) | Throughput (req/s) | Target |
|---|---|---|---|
| Upload (0.5 MB image, 5 in parallel) | 295 | 24 | No error: **0 errors out of 50** |
| Ciphertext download only (baseline) | 162 | 185 | Reference |
| Fully protected read; key decision alone | 183; key decision 80 | 121 | Key decision p95 under 300 ms: **met** |
| Revocation during the load | First refusal 140 ms after the click; **0 keys released out of 1,896 requests** made after the revocation | | Zero key released: **met** |

Cost of the protections: 21 ms at p95; throughput 121 against 185 req/s. Errors: upload 0, read 0, full 0, revoke 0. Revocation round trip 178 ms.

## §7 incident-response table

| Step | When |
|---|---|
| Detect, contain | Detected T+1.86 s; account disabled T+1.86 s; attacker's next request refused T+2.0 s |
| Analyse | 173 ms: 13 events, 12 patient references targeted, 0 keys released |

Keys obtained by the attacker: **0**; raw storage entropy 8.000 bits/byte; the pod's token got: {'grant revoked (notice received directly from the patient)': 3}.

## §8 audit table

- No unauthorised transfer: **Held**
- Breach handling: **Held**: detected and contained in 1.86 s, 0 keys obtained, analysed from the audit chain in 173 ms
