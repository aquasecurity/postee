#!/bin/sh
kubectl create configmap alm-config -n aqua --from-file=cfg.yaml
