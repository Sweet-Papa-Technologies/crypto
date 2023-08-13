declare module 'browser-crypto' {
  export const Buffer: any; // Buffer made for Browser environments
  export function createCipheriv(...args: any[]): any; // Function to create a Cipher
  export function createDecipheriv(...args: any[]): any; // Function to create a Decipher
  export function getCiphers(): any; // Function to get Ciphers
  export function createECDH(curve: string): any; // Function to create ECDH
  export function createCipher(algorithm: string, key: any): any; // Deprecated, use createCipheriv() instead
  export function createDecipher(algorithm: string, key: any): any; // Deprecated, use createDecipheriv() instead
  export function pbkdf2(password: string, salt: string, iterations: number, keylen: number, digest: string, callback: (error: Error, derivedKey: any) => void): void; // Function for pbkdf2
  export function pbkdf2Sync(password: string, salt: string, iterations: number, keylen: number, digest: string): any; // Synchronous version of pbkdf2
}