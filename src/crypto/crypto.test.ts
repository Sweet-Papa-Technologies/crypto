import { encryptString, decryptString, generatePassphrase, kyberHandshaker } from './crypto';

describe('General Encryption and Decryption', () => {
  it('should encrypt and decrypt a string with the same key', () => {
    const key = generatePassphrase();
    const plaintext = 'Hello, World!';
    const encrypted = encryptString(plaintext, key);
    const decrypted = decryptString(encrypted, key);
    expect(decrypted).toEqual(plaintext);
  });
});

describe('Kyber Handshaker', () => {

  let serverSharedSecretShared: Buffer

  it('should perform a successful key exchange', () => {
    const handshaker = new kyberHandshaker();
    const handshaker2 = new kyberHandshaker()

    const { PublicKey, PrivateKey } = handshaker.generateKeys();
    const handShakeData = handshaker2.generateKeyHandshake(PublicKey);
    const c = handShakeData.c
    const clientSharedSecret = handShakeData.ss1 as Buffer
    const serverSharedSecret = handshaker.ConsumeHandshake(c, PrivateKey);

    expect(clientSharedSecret).toEqual(serverSharedSecret);

    if (serverSharedSecret) {
      serverSharedSecretShared = serverSharedSecret
    }

  });

  it('When handshake is performed, shared secret should be used to encrypt and decrypt a message:', () => {
    if (serverSharedSecretShared) {

      const plaintext = 'Hello, World!';
      const encrypted = encryptString(plaintext, serverSharedSecretShared);
      const decrypted = decryptString(encrypted, serverSharedSecretShared);

      expect(decrypted).toEqual(plaintext);

      console.log(decrypted)

    }
  })

  // Now we should make a test to see if the client can save the shared secret to a string and send it to the server
  // The server should be able to decrypt the message with the shared secret
  it('should perform a successful key exchange', () => {

    // let's just make sure we can convert this buffer to a string
    const serverSharedSecretSharedString = kyberHandshaker.convertKeyBufferToKeyString(serverSharedSecretShared)
    expect(serverSharedSecretSharedString).toBeTruthy()
    expect(typeof serverSharedSecretSharedString).toEqual('string')

    // Now let's make sure we can convert it back to a buffer
    const serverSharedSecretSharedBuffer = kyberHandshaker.convertKeyStringToKeyBuffer(serverSharedSecretSharedString)
    expect(serverSharedSecretSharedBuffer).toBeTruthy()
    expect(typeof serverSharedSecretSharedBuffer).toEqual('object')

    // Now let's make sure we can encrypt and decrypt a message with the string
    const plaintext = 'Hello, World! AGAIIIIIN';
    const encrypted = encryptString(plaintext, serverSharedSecretSharedBuffer);
    const decrypted = decryptString(encrypted, serverSharedSecretSharedBuffer);
    expect(decrypted).toEqual(plaintext);
  });

});
