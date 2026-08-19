# Decision 0003: FIPS validation is a production release gate

- Status: accepted; gate is currently unsatisfied
- Date: 2026-08-18

Using algorithms specified by NIST is not the same as operating a FIPS 140-3
validated cryptographic module. The portable Rust provider is suitable for wire
vectors, tests, and independent implementation work only.

A production release must identify and verify:

1. CMVP certificate number and current status;
2. exact module and dependency version;
3. exact CPU, OS, and operational environment covered by the certificate;
4. approved mode/configuration and integrity self-tests;
5. coverage for every suite operation, including the selected PQC algorithms;
6. a reviewed hybrid KEM/signature composition and downgrade analysis.

The build reports this gate as **not production-authorized** until all six are
attached as release evidence. Documentation and APIs must not imply otherwise.
