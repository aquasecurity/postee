# webhook-server

docker run -d -p 8082:8082 -p 8445:8445 -e AQUAALERT_CFG=/alert.yaml -v ~/alert.yaml:/alert.yaml aquasec/webhook-server
