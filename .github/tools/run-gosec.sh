#!/usr/bin/env bash
set -e
set -o pipefail

wget https://github.com/securego/gosec/releases/download/v2.6.1/$GOSECNAME.tar.gz -O /tmp/$GOSECNAME.tar.gz
echo "80950b35d13a0f68b75878da030ee305def6170f6db01d1f8021ee198eb84b25 /tmp/$GOSECNAME.tar.gz" | sha256sum -c -

mkdir -p /tmp/$GOSECNAME
tar -C /tmp/$GOSECNAME -xzf /tmp/$GOSECNAME.tar.gz

/tmp/$GOSECNAME/gosec -conf gosec.json ./...