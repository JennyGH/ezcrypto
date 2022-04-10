#!/bin/bash

########################### NOTICE!!! ###########################
# Please make sure env variable $ANDROID_NDK exists!!!
#################################################################

# Specify compiler.
CC=gcc

# Set current dir to PROJECT_DIR
PROJECT_DIR="`pwd`"

# Specify build dir, Makefile will be generated to here:
BUILD_DIR_NAME=build-android
BUILD_DIR_PATH="$PROJECT_DIR/$BUILD_DIR_NAME"

# Specify build type, Debug or Release.
BUILD_TYPE=Release

# Specify API Version of Android.
ANDROID_API_VERSION=23

# Specify install dir, binary files will be installed to here.
INSTALL_DIR="$PROJECT_DIR/built/android"

do_compile(){
    mkdir -p "$BUILD_DIR_PATH-$ARCH"
    cd "$BUILD_DIR_PATH-$ARCH"
    cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
          -DANDROID_TOOLCHAIN=$CC                                                 \
          -DANDROID_ABI=$ARCH                                                     \
          -DANDROID_NDK=$ANDROID_NDK                                              \
          -DANDROID_PLATFORM=android-$ANDROID_API_VERSION                         \
          -DCMAKE_BUILD_TYPE=$BUILD_TYPE                                          \
          -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR/$ARCH"                             \
          -DCMAKE_VERBOSE_MAKEFILE=FALSE                                          \
          ..
    cmake --build .                \
          --config $BUILD_TYPE     \
          -- -j $(nproc)        && \
    make install
}

for ARCH in armeabi-v7a armeabi arm64-v8a x86 x86_64 mips mips64
do
    do_compile
done