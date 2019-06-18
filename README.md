KLEE-NATIVE
=============================

# KLEE Symbolic Virtual Machine

[![Build Status](https://travis-ci.org/klee/klee.svg?branch=master)](https://travis-ci.org/klee/klee)
[![Coverage](https://codecov.io/gh/klee/klee/branch/master/graph/badge.svg)](https://codecov.io/gh/klee/klee)

`KLEE` is a symbolic virtual machine built on top of the LLVM compiler
infrastructure. Currently, there are two primary components:

  1. The core symbolic virtual machine engine; this is responsible for
     executing LLVM bitcode modules with support for symbolic
     values. This is comprised of the code in lib/.

  2. A POSIX/Linux emulation layer oriented towards supporting uClibc,
     with additional support for making parts of the operating system
     environment symbolic.

Additionally, there is a simple library for replaying computed inputs
on native code (for closed programs). There is also a more complicated
infrastructure for replaying the inputs generated for the POSIX/Linux
emulation layer, which handles running native programs in an
environment that matches a computed test input, including setting up
files, pipes, environment variables, and passing command line
arguments.

For further information, see the [webpage](http://klee.github.io/).


# Build Instructions 

Build instructions (assuming you have typical KLEE dependencies like z3 installed). This assumes you're on either Ubuntu 18.04 or 16.04, but should work for 14.04 too.


1. `git clone git@github.com:trailofbits/remill.git`
2. `cd remill/tools`
3. `git clone git@github.com:trailofbits/klee.git`
4. `cd ../../`
5. `./remill/scripts/build.sh --llvm-version 7.0 --use-host-compiler`
6. `cd remill-build`
7. `make install`
8. `cd ..`

If you have an issue with the last step, or later issues with things like registering a target machine, 
then try removing `--use-host-compiler` or changing to llvm version 8.0. The build.sh script 
downloads pre-built binaries/libraries for things like LLVM, Clang, XED, etc., and sometimes there 
are ABI-related linking issues for libc++ vs. libstdc++.
