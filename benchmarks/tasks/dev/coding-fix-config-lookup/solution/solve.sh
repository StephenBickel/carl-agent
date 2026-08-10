#!/bin/sh
set -eu
sed -i.bak 's/(default, config_file, environment, cli)/(cli, environment, config_file, default)/' config_lookup.py
rm config_lookup.py.bak
