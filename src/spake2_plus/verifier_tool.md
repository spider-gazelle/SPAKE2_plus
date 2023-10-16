# SPAKE2+ Crystal Tool

SPAKE2+ Crystal Tool is a Crystal script for generating SPAKE2+ protocol
parameters (only Verifier as of today). SPAKE2+ protocol is used during Matter
commissioning to establish a secure session between the commissioner and the
commissionee.

## Usage Examples

To list all available subcommands:

```console
$ ./verifier_tool --help
usage: ./verifier_tool [subcommand] [arguments]
    gen-verifier                     Generate SPAKE2+ Verifier
    -h, --help                       Show this help
```

To display parameters of the `gen-verifier` subcommand:

```console
$ ./verifier_tool gen-verifier --help
usage: ./verifier_tool gen-verifier -p PASSCODE -s SALT -i count
    -h, --help                       Show this help
    -p CODE, --passcode=CODE         8-digit passcode
    -s SALT, --salt=SALT             Salt of length 16 to 32 octets encoded in Base64
    -i COUNT, --iterations=COUNT     Iteration count between 1000 and 100000
```

To generate SPAKE2+ verifier for "SPAKE2P Key Salt" salt and 20202021 passcode,
using 1000 PBKDF2 iterations:

```console
./verifier_tool gen-verifier -p 20202021 -s U1BBS0UyUCBLZXkgU2FsdA== -i 1000
uWFwqugDNGiEck/po7KHwwMwwqZgN10XuyBajPGuyzUEV/iree4lOrao5GuwnlQ65CJzbeUB49s31EH+NEkg0JVI5MGCQGMMT/SRPFNRODm3wH/MBiehuFc6FJ/NH6Rmzw==
```
