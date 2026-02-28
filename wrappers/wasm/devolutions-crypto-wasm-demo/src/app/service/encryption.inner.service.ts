import { CiphertextVersion, KeyVersion, KeyPair, PrivateKey, PublicKey, Argon2Parameters, PasswordHashVersion } from '@devolutions/devolutions-crypto-web';
export { CiphertextVersion, KeyVersion, KeyPair, PrivateKey, PublicKey, Argon2Parameters, PasswordHashVersion } from '@devolutions/devolutions-crypto-web';
import * as devolutionsCrypto from '@devolutions/devolutions-crypto-web';

export function encrypt(data: Uint8Array, key: Uint8Array, version?: CiphertextVersion): Uint8Array {
    return devolutionsCrypto.encrypt(data, key, undefined, version);
}

export function encryptAsymmetric(data: Uint8Array, publicKey: PublicKey, version?: CiphertextVersion): Uint8Array {
  return devolutionsCrypto.encryptAsymmetric(data, publicKey, undefined, version);
}

export function decrypt(data: Uint8Array, key: Uint8Array): Uint8Array {
    return devolutionsCrypto.decrypt(data, key);
}

export function decryptAsymmetric(data: Uint8Array, privateKey: PrivateKey): Uint8Array {
    return devolutionsCrypto.decryptAsymmetric(data, privateKey);
}

export function deriveKeyPbkdf2(key: Uint8Array, salt?: Uint8Array, iterations?: number, length?: number): Uint8Array {
    return devolutionsCrypto.deriveKeyPbkdf2(key, salt, iterations, length);
}

export function base64decode(value: string): Uint8Array {
    return devolutionsCrypto.base64decode(value);
}

export function base64encode(data: Uint8Array): string {
    return devolutionsCrypto.base64encode(data);
}

export function generateSharedKey(nShares: number, threshold: number, length?: number): Uint8Array[] {
    return devolutionsCrypto.generateSharedKey(nShares, threshold, length);
}

export function joinShares(shares: Uint8Array[]): Uint8Array {
    return devolutionsCrypto.joinShares(shares);
}

export function generateKey(length?: number): Uint8Array {
    return devolutionsCrypto.generateKey(length);
}

export function hashPassword(password: Uint8Array, iterations?: number, version?: PasswordHashVersion): Uint8Array {
    return devolutionsCrypto.hashPassword(password, iterations, version);
}

export function verifyPassword(password: Uint8Array, hash: Uint8Array): boolean {
    return devolutionsCrypto.verifyPassword(password, hash);
}

export function generateKeyPair(version?: KeyVersion): KeyPair {
    return devolutionsCrypto.generateKeyPair(version);
}

export function mixKeyExchange(privateKey: PrivateKey, publicKey: PublicKey): Uint8Array {
    const result = devolutionsCrypto.mixKeyExchange(privateKey, publicKey);
    return result;
}
