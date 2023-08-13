
import {
  Buffer,
  createCipheriv,
  createDecipheriv
} from 'browser-crypto';



const kyber = require ('crystals-kyber')

export function encryptString(data: string, key: string | Buffer) {
  const bufferObject = typeof key === 'string' ? Buffer.from(key, 'hex') : key
  const iv = Buffer.alloc(16);
  const cipher = createCipheriv('aes-256-cbc', bufferObject, iv);
  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return JSON.stringify({ iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') });
}

export function decryptString(encryptedString: string, key: string | Buffer) {
  const { iv, encryptedData } = JSON.parse(encryptedString);
  const bufferObject = typeof key === 'string' ? Buffer.from(key, 'hex') : key

  const decipher = createDecipheriv('aes-256-cbc', bufferObject, Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(Buffer.from(encryptedData, 'hex'));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}


export function generatePassphrase(passpharse:number[]=[]) {
  const key = passpharse.length > 0 ? Buffer.from(passpharse) : Buffer.alloc(32);; // 32 bytes for AES-256
  const keySecret = key.toString('hex'); // Convert to hex string
  return keySecret
}

export class kyberHandshaker {

  private privateKey:number[]|string=''
  publicKey:number[]|string=''

  generateKeys(){
    let pk_sk = kyber.KeyGen1024();
    let pk = pk_sk[0] as number[];
    let sk = pk_sk[1] as number[];

    this.privateKey = sk 
    this.publicKey =pk 
    return {PublicKey: pk, PrivateKey: sk}
  }

  generateKeyHandshake(PublicKey:number[]|string){
    if (typeof PublicKey === 'string' ){
      PublicKey = JSON.parse(PublicKey) as number[]
    }
    let c_ss = kyber.Encrypt1024(PublicKey);
    let c = c_ss[0];
    let ss1 = c_ss[1];
    console.log(ss1)
    return {c: c, ss1: ss1}
  }

  ConsumeHandshake(secretPasswordEncrypted:number[]|string, PrivateKey:number[]|string=this.privateKey){
    if (typeof secretPasswordEncrypted === 'string' ){
      secretPasswordEncrypted = JSON.parse(secretPasswordEncrypted) as number[]
    }

    if (typeof PrivateKey === 'string' ){
      PrivateKey = JSON.parse(PrivateKey) as number[]
    }

    if (PrivateKey){
      let ss2 = kyber.Decrypt1024(secretPasswordEncrypted,PrivateKey) as Buffer
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