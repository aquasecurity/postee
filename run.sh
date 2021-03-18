#!/bin/sh
docker run -d -p 8082:8082 -p 8445:8445 -e AQUAALERT_CFG=/alert.yaml -v ~/upwork/aquasec/webhook-server/alert.yaml:/alert.yaml aquasec/postee
