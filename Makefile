PY ?= python3

.PHONY: measure-all install up down portal setup scene1 scene2 scene3 scene5 watch erase demo load redteam g4 measure test reset image

install:            ## install Python dependencies
	$(PY) -m pip install -r requirements.txt

up:                 ## start the local stack from scratch (S3 emulator + HDG + hospital services)
	$(PY) demo/stack.py start --fresh

down:               ## stop everything
	$(PY) demo/stack.py stop

setup:              ## synthetic DICOM, patient enrollment, first consent
	$(PY) demo/scenes.py setup

portal:             ## start the patient portal on http://127.0.0.1:8301 (after setup)
	$(PY) demo/stack.py portal

scene1:             ## HDG only ever sees ciphertext
	$(PY) demo/scenes.py scene1

scene2:             ## revocation cuts access at once; erasure = crypto-shredding
	$(PY) demo/scenes.py scene2

scene3:             ## any edit to the audit log is detected
	$(PY) demo/scenes.py scene3

scene5:             ## the AI job never sees or outputs an identity; revoked patient excluded
	$(PY) demo/scenes.py scene5

watch:              ## live key requests every 100 ms (click Revoke in the portal)
	$(PY) demo/scenes.py watch

erase:              ## crypto-shredding: destroy the patient key, try to restore
	$(PY) demo/scenes.py erase

demo: up            ## run every scene end to end and print 15 checks
	$(PY) demo/scenes.py all

load:               ## load tests (run after `make up`)
	$(PY) demo/loadtest.py --mode upload --count 50 --concurrency 5
	$(PY) demo/loadtest.py --mode read --seconds 30 --concurrency 20
	$(PY) demo/loadtest.py --mode full --seconds 30 --concurrency 20
	$(PY) demo/loadtest.py --mode revoke --seconds 30 --concurrency 20

redteam:            ## phished clinician attack: detection, containment, analysis (after `make up`)
	$(PY) demo/redteam.py

g4:                 ## G4 with Docker: nothing on the HDG network reaches the internet
	bash demo/g4_egress.sh

measure:            ## EVERYTHING for the report: demo, G5, load tests, red team -> measurements/*/SUMMARY.md
	$(PY) demo/measure.py

measure-all:        ## same, plus the G4 Docker test
	$(PY) demo/measure.py --with-g4

test:               ## end-to-end test
	$(PY) -m pytest -q tests

reset: down         ## wipe all local state
	rm -rf var

image:              ## build the container image used by docker compose and k3s
	docker build -t nexus-poc:0.1 -f deploy/Dockerfile .
