# BatchPIR protocol for FABLE

This repository contains an implementation of PIRANA (https://eprint.iacr.org/2022/1401), which is modified for the use of FABLE (https://eprint.iacr.org/2025/1081). The implementation is based on https://github.com/mhmughees/vectorized_batchpir rather than PIRANA's official implementation, because it was not released at the time we develop FABLE. 

> [!WARNING]
> This library is not intended to be used as a standalone implementation for batchPIR, as it contains a lot of modifications tailored for FABLE. You don't need to build and install this library if you intend to build FABLE (https://github.com/timzsu/FABLE). 

## Build the code as a standalone library

Although the code is not intended to be built as a standalone library, you could still build it and run it as a PIR protocol. 

To build the repository, first install the following libraries globally. 

- [SEAL v4.1.1](https://github.com/microsoft/SEAL/tree/v4.1.1)
- [fmt](https://github.com/fmtlib/fmt)
- [libOTe](https://github.com/osu-crypto/libOTe)

To build the project, run
```bash
cmake -S . -B build -DLUT_INPUT_SIZE=20 -DLUT_OUTPUT_SIZE=64
cmake --build build --parallel
```

Once the build process is complete, run the following command to execute the Batch PIR:

```bash
./build/bin/vectorized_batch_pir
```

## Acknowledgment

We appreciate [Muhammad Haris Mughees](https://mhmughees.github.io) for the open-sourced implementation of batch PIR. 
