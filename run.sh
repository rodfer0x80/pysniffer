#!/bin/bash

docker build \
    -t python_script \
    .

docker run \
    --rm \
    -it \
    -v $(pwd)/src:/src python_script \
    python /src/main.py \