#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##
CC_PRE=$CC
CXX_PRE=$CXX

export CXX=clang++
export CC=clang
cd /RLTG
make clean all
pushd llvm_mode; make clean all; popd
#pushd distance_calculator; cmake -G Ninja ./; cmake --build ./; popd

export CC=$CC_PRE
export CXX=$CXX_PRE
