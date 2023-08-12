import crypto from 'crypto';

const kyber = require ('crystals-kyber')

export function encryptString(data: string, key: string | Buffer) {
  const bufferObject = typeof key === 'string' ? Buffer.from(key, 'hex') : key
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', bufferObject, iv);
  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return JSON.stringify({ iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') });
}

export function decryptString(encryptedString: string, key: string | Buffer) {
  const { iv, encryptedData } = JSON.parse(encryptedString);
  const bufferObject = typeof key === 'string' ? Buffer.from(key, 'hex') : key

  const decipher = crypto.createDecipheriv('aes-256-cbc', bufferObject, Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(Buffer.from(encryptedData, 'hex'));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}


export function generatePassphrase(passpharse:number[]=[]) {
  const key = passpharse.length > 0 ? Buffer.from(passpharse) : crypto.randomBytes(32); // 32 bytes for AES-256
  const keySecret = key.toString('hex'); // Convert to hex string
  return keySecret
}

export class kyberHandshaker {

  private privateKey:number[]|string=''
  publicKey:number[]|string=''

  generateServerKeys(){
    let pk_sk = kyber.KeyGen1024();
    let pk = pk_sk[0] as number[];
    let sk = pk_sk[1] as number[];

    this.privateKey = sk 
    this.publicKey =pk 
    return {serverPublicKey: pk, serverPrivateKey: sk}
  }

  generateClientKeyHandshake(serverPublicKey:number[]|string){
    if (typeof serverPublicKey === 'string' ){
      serverPublicKey = JSON.parse(serverPublicKey) as number[]
    }
    let c_ss = kyber.Encrypt1024(serverPublicKey);
    let c = c_ss[0];
    let ss1 = c_ss[1];
    console.log(ss1)
    return {c: c, ss1: ss1}
  }

  serverConsumeClientKeyHandshake(secretPasswordEncrypted:number[]|string, serverPrivateKey:number[]|string=this.privateKey){
    if (typeof secretPasswordEncrypted === 'string' ){
      secretPasswordEncrypted = JSON.parse(secretPasswordEncrypted) as number[]
    }

    if (typeof serverPrivateKey === 'string' ){
      serverPrivateKey = JSON.parse(serverPrivateKey) as number[]
    }

    if (serverPrivateKey){
      let ss2 = kyber.Decrypt1024(secretPasswordEncrypted,serverPrivateKey) as Buffer
      return ss2
    }
    return null
  }

  static convertKeyBufferToKeyString(keyBuffer:Buffer){
    return keyBuffer.toString('hex')
  }

  static convertKeyStringToKeyBuffer(keyString:string){
    return Buffer.from(keyString,'hex')
  }
}

export default {
  kyberHandshaker,
  generatePassphrase,
  decryptString,
  encryptString
}