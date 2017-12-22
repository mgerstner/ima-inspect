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
is currently no support for recursive listing of directories at the moment.

You can limit the output to only the `security.evm` or `security.ima`
attribute by specifying the command line switch `-a ima` or `-a evm`,
respectively.

You can extract the plain cryptographic primitive from the attribute by
specifying both `-a` and `--out <hex, bin>`. The cryptographic primitive is
the plain signature, digest or HMAC depending on the subtype of the attribute.
With this you can for example verify IMA signatures from userspace like this:

```sh
$ ima_inspect some_file -o bin -a ima >ima_signature.bin
$ openssl dgst -sha256 -verify ima_public.pem -keyform PEM -signature ./ima_signature.bin some_file
```

Remember that the digest algorithm and public key must match the ones used in
the `security.ima` attribute.

## Building

`ima_inspect` requires the following dependencies:

- the TCLAP C++ command line parsing library
- the ima-emv-utils (development files)
- the libattr development files

The build system is autotools based and should work as usual.


## License

Please refer to the LICENSE file.
