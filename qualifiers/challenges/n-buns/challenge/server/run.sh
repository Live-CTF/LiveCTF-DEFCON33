#!/bin/sh

sed -i "s/LiveCTF{PLACEHOLDER_FLAG}/$FLAG/" .config.toml
#unset FLAG # Server uses env variable

nsjail --config nsjail.conf
