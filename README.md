# SupermicroFirmwareVerifier
A tool that checks the digital signature on supermicro firmware.

# WHAT

1. Supermicro(tm) firmware binaries are signed with a pkcs7 digital
signature. The authenticity of the firmware can be accomplished by
independent third parties, and SMC is at pains to assure everyone that
the tools used for firmware verification are industry standard
(openssl, pkcs7, sha256).

2. Supermicro is not distributing any code to verify the firmware
independently, although they distribute a binary at request that
accomplishes this. However, the binary is under NDA and the
corresponding source code is not available.

3. This project attempts to make up the shortfall by providing a
transparent utility with which anyone can verify the authenticity of
Supermicro firmware binaries.

# HOW

The largest problem in verifying SMC firmware is that the locations of
digital signatures, public keys and such are not published by
SMC. However, the firmware is available for anyone to look at, and is
distributed as a set of UEFI volumes, lending itself to analysis by
`uefi-firmware-parser` [TODO: insert reference].

The way firmware signature verification proceeds is as follows:

* Identify the location of, and extract, `<pubcert>`, the X509 SMC
  public certificate. Check the authenticity of the certificate.

  [TODO] how

* From `<pubcert>` extract `<pubkey>`, the (RSA) public key from the
  certificate.

  ```
  openssl ....
  ```

* Identify the location of the firmware's pkcs7 digital
  signature. Extract `<sig>`, the 256 byte sequence that represents
  the encrypted signature.

* Identify and interpret the table used to determine which parts of
  the firmware are covered by the signature.

* Following the table, scan the firmware and collect `<digest>`, a
  sha256 digest of the components of firmware covered by the
  signature.

* Using the RSA public key, verify the collected digest against the
  digital signature.
  ```
  openssl dgst -verify <pubkey> -signature <sig> <digest>
  ```
