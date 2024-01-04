## DRAFT

- test suite from https://asn1.io/asn1playground/default.aspx
- cargo r -- --help


# compiler bin
ninomae hello.asn1 -o hello.ber


# cargo inspired
ninomae new hello && cd hello
ninomae compile -bd  # ber, der formats
ninomae view path/to.ber
ninomae decode path/to.ber -aj  # asn1, jer outputs
ninomae decode euicc  # looks for file name in src

precompiled/
    some.ber
src/
    euicc.asn1
target/
    encode/
        euicc/
            euicc.ber
            euicc.der
    decode/
        precompiled/
            some.asn1
            some.jer
        euicc/
            euicc.asn1
            euicc.jer
