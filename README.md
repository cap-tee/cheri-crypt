# CHERI-Crypt

This repository contains Proteus: a configurable CHERI-based RISC-V core developed from https://github.com/proteus-core/proteus (commit ref 968276b), which has been extended with the CHERI-Crypt plugin.

This is a proof of concept design to encrypt sealed capabilities within a CHERI-based enclaved TEE, as discussed in our TCHES 2025 paper "CHERI-Crypt: Transparent Memory Encryption on Capability Architectures".

*Our project is funded by the Digital Security by Design (DSbD) Programme delivered by UKRI to support the DSbD ecosystem.*



## Setting up and running CHERI-Crypt

This setup information is intended for minimal installation to run the CHERI-Crypt basic simulation tests. For more information refer to the [proteus documentation.](./proteus/README.md) The set up was tested on Ubuntu 18.04.

Minimum pre-requisites for building the **CHERI-Crypt cores**:

* **SBT**: build tool for scala (and hence SpinalHDL)
* **Verilator** - needed by SBT for running scala simulations
* **GTK** - to view scala simulation waveforms
* **Open JDK** - used by Scala

Minimum pre-requisites for building the  **basic CHERI-Crypt assembly tests** to go on the cores:

* **RV32I(M) GNU tool chain** - RISC-V C and C++ cross-compiler. It supports two build modes: a generic ELF/Newlib toolchain and a more sophisticated Linux-ELF/glibc toolchain.
* **llvm-cheri** - used for compiling cheri-based code 

## Step 1: Install Verilator, GTK, Open JDK

```
sudo apt-get install openjdk-11-jdk verilator curl make gcc g++ gtkwave
```
## Step 2: Install SBT - https://www.scala-sbt.org/

```
echo "deb https://repo.scala-sbt.org/scalasbt/debian all main" | sudo tee /etc/apt/sources.list.d/sbt.list
 echo "deb https://repo.scala-sbt.org/scalasbt/debian /" | sudo tee /etc/apt/sources.list.d/sbt_old.list
 curl -sL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x2EE0EA64E40A89B84B2DF73499E82A75642AC823" | sudo apt-key add
 sudo apt-get update
 sudo apt-get install sbt
```

## Step 3: Clone this repository under ~/projects

```
git clone --recurse-submodules https://github.com/cap-tee/cheri-crypt.git
```
## Step 4: Clone and Install An RV32I(M) toolchain

https://github.com/riscv/riscv-gnu-toolchain. *Takes about 2hrs to clone and build*

```
git clone --recurse-submodules https://github.com/riscv-collab/riscv-gnu-toolchain.git
```
Note that the project was tested with commit ref d9219c0. Although newer versions should work, this version can be checked out if necessary using `git checkout d9219c0`.

**Install RV32I(M) dependencies which are needed to build the tool chain**

```
sudo apt-get install autoconf automake autotools-dev curl python3 libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev
```
**Set environment variables for riscv32IM**

Add to path, edit `.bashrc` in home directory

```
export PATH=/opt/riscv/bin:$PATH
```

**Configure with rv32im**
make sure in `/riscv-gnu-toolchain` directory. For later versions use `--with-arch=rv32im_zicsr`

```
 ./configure --prefix=/opt/riscv --with-arch=rv32im --with-abi=ilp32

sudo make  
``` 

## Step 5: Build llvm-cheri with modifications to include new encryption instructions

llvm-cheri is provided as a submodule to this repository. Install dependencies:

```
sudo apt install cmake ninja-build python-pip

pip install pyelftools
```

Under Ubuntu 18.04, cmake will not be new enough to perform the build. Go to
https://apt.kitware.com for instructions on how to get the latest build.

```
sudo apt-get update

sudo apt-get install gpg wget

wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | sudo tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null

echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ bionic main' | sudo tee /etc/apt/sources.list.d/kitware.list >/dev/null

sudo apt-get update
sudo rm /usr/share/keyrings/kitware-archive-keyring.gpg

sudo apt-get install kitware-archive-keyring
sudo apt-get install cmake
```

Under `/llvm-cheri`, perform set up, then build. *Takes about 2hrs to build*

```
mkdir build

cd build

cmake -DCMAKE_INSTALL_PREFIX=/home/<path>/llvm-cheri/build -DLLVM_TARGETS_TO_BUILD=RISCV -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_BUILD_TYPE=Release -GNinja ../llvm/ -DLLVM_PARALLEL_LINK_JOBS=1 -DLLVM_USE_SPLIT_DWARF=ON -DBUILD_SHARED_LIBS=ON -Wno-dev

ninja -j1
```

Add to path, edit `.bashrc` under home
```
export PATH=/home/<path>/llvm-cheri/build/bin:$PATH
```

## Step 6: Run CHERI-Crypt tests

The Makefile under the top level tests directory is set up to run the CHERI-Crypt basic tests. From the `proteus` directory add the `cheriencrypt` tests as the custom test directory:
```
export CUSTOM_TESTS_DIR=/home/<path>/proteus/src/main/scala/riscv/plugins/cheriEncrypt/tests
```
Then run the tests
```
make -C tests
```

To view the simulation of the last test
```
gtkwave sim.vcd
```

For further test information see [/proteus/src/main/scala/riscv/plugins/cheriEncrypt/tests/README.md](./proteus/src/main/scala/riscv/plugins/cheriEncrypt/tests/README.md)