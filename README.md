# @fofonet/crypto SDK

The @fofonet/crypto SDK is a cryptographic library that facilitates secure key generation, sharing, encryption, and decryption using the Kyber 1024 Handshaker.

## Table of Contents
0. [About](#about)
1. [Installation](#installation)
2. [Usage](#usage)
3. [API Reference](#api-reference)
4. [License](#license)

## About

### Encryption Details

#### AES-256 Asymmetrical Encryption
For the data itself that needs to be encrypted/decrypted, AES-256 asymmetrical encryption is utilized. This encryption method is currently understood to be difficult for Quantum Computers to crack.

#### Key Exchange with Crystals Kyber Algorithm
To allow both parties in the encrypted transfer to encrypt and decrypt data via that AES-256 key, the Crystals Kyber algorithm with a 1024-bit key is used. This encryption is on par with AES-256 encryption, and is currently a canidate for NIST PQC safe encryptions.

### Introduction to Crystals Kyber
Kyber is an IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one of the finalists in the NIST post-quantum cryptography project, with various parameter sets aiming at different security levels.

More information here: https://www.ibm.com/docs/en/zos/2.5.0?topic=cryptography-crystals-kyber-algorithm

## Installation

Install the SDK using npm:

```bash
npm install @fofonet/crypto
```

## Usage
This section describes how to use the SDK to generate and share keys, with a client doing an exchange with a server. Follow these steps to utilize the SDK.

### Basic Example

#### Step 1 (Client Side) | Generate Pub/Prv Keys and Send Public Key to Server

```typescript
import { kyberHandshaker } from '@fofonet/crypto';

const handshaker = new kyberHandshaker();
const { PublicKey, PrivateKey } = handshaker.generateKeys();
```

#### Step 2 (Server Side) | Use Public Key to Accept Handshake and Generate Handshake Data

```typescript
import { kyberHandshaker } from '@fofonet/crypto';

const handshaker2 = new kyberHandshaker()
const handShakeData = handshaker2.generateKeyHandshake(PublicKey); // Pass the PublicKey generated in Step 1
const SharedSecret = handShakeData.ss1 as Buffer;

returnToClient(handShakeData.c);
```

#### Step 3 (Client Side) | Accept Handshake Data to Receive the Shared Secret

```typescript
const SharedSecret = handshaker.ConsumeHandshake(c, PrivateKey);
```

#### Step 4 (Server / Client Side) | Each side can now encrypt or decrypt messages to one another:

```typescript
import { encryptString, decryptString } from '@fofonet/crypto';

const plaintext = 'Hello, World!';
const encrypted = encryptString(plaintext, SharedSecret);
const decrypted = decryptString(encrypted, SharedSecret);
```

## API Reference
Here, you can describe each function and class in detail, including parameters and return values. Check the source code for complete details.
### Module Functions / Classes
##### `function encryptString(data: string, key: string | Buffer): string`
Encrypts a string using AES-256. Takes a key generated using `generatePassphrase` a key ultimately generated by `generateKeyHandshake` or `ConsumeHandshake` from the *kyberHandshaker* class.

##### `function decryptString(encryptedString: string, key: string | Buffer): string`
Decrypts an encrypted string using AES-256. Takes a key generated using `generatePassphrase` a key ultimately generated by `generateKeyHandshake` or `ConsumeHandshake` from the *kyberHandshaker* class.

##### `function generatePassphrase(passphrase: number[] = []): string`
Generates a random passpharse for use with the `decryptString` or `encryptString` functions.

### `class kyberHandshaker` 

#### Class Description

The `kyberHandshaker` class provides a secure way to establish an encrypted connection between two parties. It leverages the Crystals Kyber algorithm for secure key exchange, and then AES-256 encryption for the data itself.

#### Class Methods

##### `generateKeys()`

This method generates a pair of public and private keys using the Kyber algorithm.
**Returns:** An object containing the public and private keys.

##### `generateKeyHandshake(publicKey)`

This method accepts the public key from the other party and generates the handshake data, including the shared secret.
**Parameters:** publicKey - The public key from the other party.
**Returns:** An object containing the handshake data.

##### `ConsumeHandshake(c, privateKey)`

This method accepts the handshake data from the server and the client's private key to derive the shared secret.
**Parameters:**
- c - The handshake data from the server.
- privateKey - The client's private key.
**Returns:** The shared secret as a Buffer.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.