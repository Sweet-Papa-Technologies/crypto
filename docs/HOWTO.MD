## How to Use
This will describe how to use the SDK to generate and share keys. We will assume a client is doing an exchange with a server.

### Basic Example

#### Step 1 (Client Side) | Generate Pub/Prv Keys and Send Public Key to Server

```
import { encryptString, decryptString, generatePassphrase, kyberHandshaker } from '@fofonet/crypto';

const handshaker = new kyberHandshaker();

const { PublicKey, PrivateKey } = handshaker.generateKeys();

```

#### Step 2 (Server Side) | Use Public Key to Accept Handshake and Generate Handshake Data

```
import { encryptString, decryptString, generatePassphrase, kyberHandshaker } from '@fofonet/crypto';

const handshaker2 = new kyberHandshaker()

const handShakeData = handshaker2.generateKeyHandshake(serverPublicKey);
const c = handShakeData.c

// At this point, the server now has the secret!
const SharedSecret = handShakeData.ss1 as Buffer

// We need to return the const 'c' to the client so they may know the secret!
returnToClient(c)

```

#### Step 3 (Client Side) | Accept Handshake Data to Recieve the Shared Secret
```
    // Client side, we use our Private Key to get the secret that the server side knows
    const SharedSecret = handshaker.ConsumeHandshake(c, PrivateKey);

```

#### Step 4 (Server / Client Side) | Each side can now encrypt or decrypt messages to one another:
```
      const plaintext = 'Hello, World!';

      const encrypted = encryptString(plaintext, SharedSecret);

      const decrypted = decryptString(encrypted, SharedSecret);

```