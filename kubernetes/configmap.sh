#!/bin/sh
kubectl create configmap postee-config -n aqua --from-file=cfg.yaml
