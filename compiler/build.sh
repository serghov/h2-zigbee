#!/bin/sh -ex
# Build clang (C frontend, BPF backend only) for wasm32-wasip1.
# Adapted from https://github.com/YoWASP/clang/blob/main/build.sh
# Source: YoWASP/llvm-project @ 97196c8 (LLVM 22.1.0 + WASI portability patch)
cd "$(dirname "$0")"
ROOT=$(pwd)

WASI_SDK_PATH=$ROOT/wasi-sdk-29.0-x86_64-linux
WASI_TARGET=wasm32-wasip1
JOBS=${JOBS:-$(nproc)}

WASI_CFLAGS="--sysroot ${WASI_SDK_PATH}/share/wasi-sysroot -mcpu=lime1 -D_WASI_EMULATED_MMAN -flto=thin"
WASI_LDFLAGS="--sysroot ${WASI_SDK_PATH}/share/wasi-sysroot -lwasi-emulated-mman -flto=thin"
# clang can need a lot of memory and stack
WASI_LDFLAGS="$WASI_LDFLAGS -Wl,--max-memory=4294967296 -Wl,-z,stack-size=8388608,--stack-first -Wl,--strip-all"
WASI_LDFLAGS="$WASI_LDFLAGS -Wl,--thinlto-jobs=${JOBS}"

cat >Toolchain-WASI.cmake <<END
set(CMAKE_SYSTEM_NAME WASI)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR wasm32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_C_COMPILER ${WASI_SDK_PATH}/bin/clang)
set(CMAKE_C_COMPILER_TARGET ${WASI_TARGET})
set(CMAKE_CXX_COMPILER ${WASI_SDK_PATH}/bin/clang++)
set(CMAKE_CXX_COMPILER_TARGET ${WASI_TARGET})
set(CMAKE_LINKER ${WASI_SDK_PATH}/bin/wasm-ld)
set(CMAKE_AR ${WASI_SDK_PATH}/bin/ar)
set(CMAKE_RANLIB ${WASI_SDK_PATH}/bin/ranlib)
set(CMAKE_C_FLAGS "${WASI_CFLAGS}")
set(CMAKE_CXX_FLAGS "${WASI_CFLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${WASI_LDFLAGS}")
END

COMMON="-G Ninja -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DLLVM_INCLUDE_UTILS=OFF -DLLVM_INCLUDE_RUNTIMES=OFF -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_INCLUDE_DOCS=OFF \
  -DLLVM_BUILD_TOOLS=OFF -DLLVM_TARGETS_TO_BUILD=BPF -DLLVM_ENABLE_PROJECTS=clang \
  -DCLANG_BUILD_TOOLS=OFF -DCLANG_INCLUDE_TESTS=OFF -DCLANG_BUILD_EXAMPLES=OFF -DCLANG_INCLUDE_DOCS=OFF \
  -DLLVM_ENABLE_ZLIB=OFF -DLLVM_ENABLE_ZSTD=OFF -DLLVM_ENABLE_LIBXML2=OFF -DLLVM_ENABLE_TERMINFO=OFF"

# 0. local LLVM patches (on top of YoWASP's WASI patch)
for p in $ROOT/patches/*.patch; do
  if git -C llvm-src apply --check "$p" 2>/dev/null; then git -C llvm-src apply "$p"; fi
done

# 1. native table generators
if ! [ -x tblgen-build/bin/clang-tblgen ]; then
  cmake -B tblgen-build -S llvm-src/llvm $COMMON -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++
  ninja -C tblgen-build -j$JOBS llvm-tblgen clang-tblgen llvm-min-tblgen
fi

# 2. clang for wasm32-wasip1
cmake -B wasm-build -S llvm-src/llvm $COMMON \
  -DCMAKE_TOOLCHAIN_FILE=$ROOT/Toolchain-WASI.cmake \
  -DLLVM_NATIVE_TOOL_DIR=$ROOT/tblgen-build/bin \
  -DLLVM_ENABLE_ASSERTIONS=OFF \
  -DLLVM_BUILD_SHARED_LIBS=OFF -DLLVM_ENABLE_PIC=OFF -DLLVM_BUILD_STATIC=ON \
  -DLLVM_ENABLE_THREADS=OFF -DLLVM_ENABLE_BACKTRACES=OFF -DLLVM_ENABLE_CRASH_OVERRIDES=OFF \
  -DLLVM_ENABLE_PLUGINS=OFF -DLLVM_ENABLE_LIBEDIT=OFF -DLLVM_ENABLE_LIBPFM=OFF \
  -DLLVM_DEFAULT_TARGET_TRIPLE=bpfel \
  -DCLANG_ENABLE_ARCMT=OFF -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_OBJC_REWRITER=OFF \
  -DCLANG_PLUGIN_SUPPORT=OFF \
  -DCLANG_RESOURCE_DIR=/lib/clang -DDEFAULT_SYSROOT=/
ninja -C wasm-build -j$JOBS clang clang-resource-headers

# 3. binaryen size optimization (~ -19%)
BINARYEN=$ROOT/binaryen-version_125
if ! [ -x $BINARYEN/bin/wasm-opt ]; then
  curl -L https://github.com/WebAssembly/binaryen/releases/download/version_125/binaryen-version_125-x86_64-linux.tar.gz | tar xzf -
fi
mkdir -p dist
cp wasm-build/bin/clang-22 dist/clang-raw.wasm
$BINARYEN/bin/wasm-opt -Oz --enable-bulk-memory --enable-sign-ext --enable-mutable-globals \
  --enable-nontrapping-float-to-int --enable-multivalue --enable-reference-types \
  --enable-call-indirect-overlong --enable-extended-const dist/clang-raw.wasm -o dist/clang.wasm
ls -l dist/
