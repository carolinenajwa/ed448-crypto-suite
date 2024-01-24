# Elliptic Curve448-Goldilocks Java-based Library and Application  #

---

# Cryptographic Library & Application

## Overview
This project comprises a cryptographic library and application implementing SHA-3 derived functions and elliptic curve cryptography. It adheres to NIST Special Publication 800-185 guidelines and utilizes the Ed448-Goldilocks elliptic curve as per NIST FIPS 186-5.

## Features
- **SHA-3 Implementation**: Incorporates KMACXOF256 for hash computation and MAC generation.
- **Elliptic Curve Cryptography**: Uses Ed448-Goldilocks for digital signatures and asymmetric encryption.
- **Digital Signatures**: Implements Schnorr signatures for secure data authentication.
- **Encryption & Decryption**: Supports data file encryption and decryption using public and private keys.

## File Structure
- `src/text_files/`: Contains essential text files like passphrase, keys, and encrypted/decrypted messages.

## Getting Started
1. Download and open folder Ed448-master in chosen IDE.  
1. Ensure necessary files are in `src/text_files/`.
2. Run the application with specified command line arguments (refer to user guide for details).
3. Navigate through main menu and submenus for various cryptographic operations.

## Command Line Arguments
- Passphrase, message, public/private key paths, encrypted/decrypted message paths, and signature file paths.

## Usage
- Generate elliptic key pairs, encrypt/decrypt files, sign/verify messages using command line and file inputs.

## Dependencies
- Java-based environment.
- NIST compliant libraries for cryptographic functions.

## Contributors
- Caroline El Jazmi
- Andy Comfort
- Brandon Morgan

_Last Updated: 12/09/2023_

---
