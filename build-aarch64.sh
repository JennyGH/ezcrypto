#!/bin/bash
PREFIX=aarch64-linux-gnu
export CROSS_COMPILE=$PREFIX-

# =============== Set some local variables here. ===============
# You can change the name of build directory here:
BUILD_DIR_NAME=build-aarch64

# Save project root path.
PROJECT_ROOT=`pwd`

# Get processor name.
PROCESSOR=`uname -p`

function build() {
    # Specify build type:
    BUILD_TYPE=$1

    # Specify install dir, binary files will be installed to here:
    INSTALL_DIR=$PROJECT_ROOT/built/linux/aarch64/$BUILD_TYPE

    # =================== Try to make directory. ===================
    if [ ! -d $BUILD_DIR_NAME ]; then
        mkdir $BUILD_DIR_NAME
    fi
    # ==============================================================
    cd $BUILD_DIR_NAME

    cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE                                             \
          -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"                                      \
          -DCMAKE_TOOLCHAIN_FILE="$PROJECT_ROOT/toolchains/aarch64.toolchain.cmake"  \
          -DCMAKE_VERBOSE_MAKEFILE=TRUE                                              \
          ..
    cmake --build . --config $BUILD_TYPE -- -j $(nproc)
    make install
    cd "$PROJECT_ROOT"
}

build Release