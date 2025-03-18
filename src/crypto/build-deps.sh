#!/bin/bash
# Copyright 2023 The Briolette Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit

echo "Checking for CMake . . ."
if ! type -f cmake &>/dev/null; then
  echo "CMake must be installed and in the PATH."
  exit 1
fi

echo "Checking if \$CARGO_MANIFEST_DIR is set . . ."
if test -z "$CARGO_MANIFEST_DIR"; then
  echo "CARGO_MANIFEST_DIR must be set."
  exit 1
fi

echo "Checking if \$OUT_DIR is set . . ."
if test -z "$OUT_DIR"; then
  echo "OUT_DIR must be set."
  exit 1
fi

mkdir -p $OUT_DIR/deps
cd $OUT_DIR/deps

echo "Fetching external dependencies . . ."
if [ ! -d amcl ]; then
  echo "Cloning amcl . . ."
  git clone --depth 1 https://github.com/xaptum/amcl.git
fi
if [ ! -d ecdaa ]; then
  echo "Cloning ecdaa . . ."
  git clone --depth 1 https://github.com/xaptum/ecdaa.git

  echo "Applying patches to ecdaa . . ."
  pushd ecdaa
  mkdir -p build/deps
  patch -p1 <$CARGO_MANIFEST_DIR/../../third_party/libecdaa.patch || exit 1
  popd

  # Minimum required deprecation can trigger FATAL checks in the repos 
  if test $(cmake -version | head -1 | cut -f3 -d' ' | cut -f2 -d. ) -ge 27; then
    echo "Updating minimum CMake version clauses . . ."
    pushd amcl
    grep -rl 'cmake_minimum_required(VERSION 3.1' . | xargs sed -i -e "s/VERSION 3.1/VERSION 3.5/"
    popd
    pushd ecdaa
    grep -rl 'cmake_minimum_required(VERSION 3.0' . | xargs sed -i -e "s/VERSION 3.0/VERSION 3.5/"
    popd
  fi

fi

echo "Building AMCL . . ."

unset  C_INCLUDE_PATH
export ECDAA_CURVES=FP256BN
pushd amcl
cmake . -DCMAKE_INSTALL_PREFIX=../ecdaa/build/deps -DAMCL_CURVE=${ECDAA_CURVES} -DAMCL_RSA="" -DAMCL_INCLUDE_SUBDIR=amcl -DBUILD_PYTHON=Off -DBUILD_MPIN=Off -DBUILD_WCC=Off -DBUILD_DOCS=Off  -DBUILD_SHARED_LIBS=Off -DECDAA_TPM_SUPPORT=OFF -DAMCL_CHUNK=64 -DWORD_SIZE=64
cmake --build .
cmake --build . --target install
popd

echo "Building ECDAA . . ."
pushd ecdaa/build
cmake .. -DCMAKE_BUILD_TYPE=Release -DECDAA_CURVES=${ECDAA_CURVES} -DTEST_USE_TCP_TPM=OFF -DBUILD_EXAMPLES=OFF -DBUILD_SHARED_LIBS=OFF -DAMCL_DIR=$(realpath $PWD/deps/lib/cmake/amcl/) -DECDAA_TPM_SUPPORT=OFF -DWORD_SIZE=64 -DAMCL_CHUNK=64
cmake --build .
popd


