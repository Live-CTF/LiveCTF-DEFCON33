#!/bin/bash

pipenv run python ./solve.py challenge:31337
if [ "X$1" = "Xshell" ]; then
    bash
fi
