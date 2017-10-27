# ima-inspect

## Introduction

`ima_inspect` is a small program that allows to give a human-readable
representation of the contents of the extended attributes (xattrs) that the
Linux IMA security subsystem creates and manages for files.

The ima-evm-utils located [here](https://git.code.sf.net/p/linux-ima/ima-evm-utils) 
represent the userspace part of IMA and can be used for creating signatures
and hashes for files. Depending on the kernel command line parameters the
kernel itself updates the hashes for files automatically.

Please refer to the official IMA documentation for more information.

`ima_inspect` is a purely read-only inspection utility. The original `evmctl`
tool from ima-evm-utils currently has no way to easily look into the binary
data stored in the extended attributes.


## Usage

Simply pass the files you want to inspect to the program `ima_inspect`. There
is currently no support for recursive listing and there are no behavioural 
switches.


## Building

`ima_inspect` requires the following dependencies:

- the TCLAP C++ command line parsing library
- the ima-emv-utils (development files)
- the libattr development files

The build system is autotools based and should work as usual.


## License

Please refer to the LICENSE file.
