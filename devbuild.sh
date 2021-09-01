#!/bin/sh
./tools/generate-files
cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=Debug
make -Cbuild
