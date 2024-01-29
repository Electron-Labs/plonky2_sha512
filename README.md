## Plonky2 SHA512

Contains Plonky2 implementation of [SHA-512]([https://breakdance.github.io/breakdance/](https://medium.com/@zaid960928/cryptography-explaining-sha-512-ad896365a0c1)) hash function.

Command (Runs basic benchmark) : 
```console
RUSTFLAGS=-Ctarget-cpu=native cargo run --package plonky2_sha512 --bin plonky2_sha512 --release
```

M2 Macbook Air Performance:
```console
Circuit has 5071 gates
Time taken to build the circuit the proof - 287.681709ms
Time taken to generate the proof - 737.203333ms
Time taken to verify the proof - 42ns
```
