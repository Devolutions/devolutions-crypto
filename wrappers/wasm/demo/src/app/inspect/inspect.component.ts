import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, ReactiveFormsModule } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { FaIconComponent } from '@fortawesome/angular-fontawesome';
import { faBug } from '@fortawesome/free-solid-svg-icons';
import { CommonModule } from '@angular/common';
import * as functions from '../shared/shared.component';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

const SIGNATURE = 0x0c0d;
const HEADER_SIZE = 8;

const DATA_TYPE_NAMES: Record<number, string> = {
  0: 'None',
  1: 'Key',
  2: 'Ciphertext',
  3: 'PasswordHash',
  4: 'Share',
  5: 'SigningKey',
  6: 'Signature',
  7: 'OnlineCiphertext',
  8: 'KeyDerivation',
};

const SUBTYPE_NAMES: Record<number, Record<number, string>> = {
  1: { 0: 'None', 1: 'Private', 2: 'Public', 3: 'Pair', 4: 'Secret' },
  2: { 0: 'None (treated as Symmetric)', 1: 'Symmetric', 2: 'Asymmetric' },
  3: { 0: 'None' },
  4: { 0: 'None' },
  5: { 0: 'None', 1: 'Pair', 2: 'Public' },
  6: { 0: 'None' },
  8: { 0: 'None' },
};

const VERSION_NAMES: Record<number, Record<number, string>> = {
  1: { 0: 'Latest', 1: 'V1 – Curve25519 / x25519' },
  2: { 0: 'Latest', 1: 'V1 – AES256-CBC + HMAC-SHA256', 2: 'V2 – XChaCha20-Poly1305' },
  3: { 0: 'Latest', 1: 'V1 – PBKDF2-HMAC-SHA256' },
  4: { 0: 'Latest', 1: 'V1 – Shamir Secret Sharing over GF256' },
  5: { 0: 'Latest', 1: 'V1 – Ed25519' },
  6: { 0: 'Latest', 1: 'V1 – Ed25519' },
  8: { 0: 'Latest', 1: 'V1 – PBKDF2-HMAC-SHA256', 2: 'V2 – Argon2id' },
};

export interface PayloadField {
  name: string;
  offset: number;
  size: number;
  hex: string;
  description: string;
}

export interface ParseResult {
  signatureHex: string;
  signatureValid: boolean;
  dataType: number;
  dataTypeName: string;
  subtype: number;
  subtypeName: string;
  version: number;
  versionName: string;
  totalBytes: number;
  payloadBytes: number;
  payloadFields: PayloadField[];
  error?: string;
}

function readUInt16LE(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset, true);
}

function toHex(bytes: Uint8Array, maxBytes?: number): string {
  const slice = maxBytes !== undefined ? bytes.slice(0, maxBytes) : bytes;
  const hex = Array.from(slice)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(' ');
  return maxBytes !== undefined && bytes.length > maxBytes ? hex + ' ...' : hex;
}

@Component({
  selector: 'app-inspect',
  standalone: true,
  imports: [ReactiveFormsModule, FaIconComponent, CommonModule],
  templateUrl: './inspect.component.html',
  styleUrl: './inspect.component.css',
})
export class InspectComponent implements OnInit {
  faBug = faBug;

  debugForm: FormGroup;
  parseResult: ParseResult | null = null;

  constructor(private encryptionService: EncryptionService) {
    this.debugForm = new FormGroup({
      input: new FormControl(''),
    });
  }

  ngOnInit() {}

  w3Open() {
    functions.w3_open();
  }

  w3Close() {
    functions.w3_close();
  }

  async decode() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;
    const input: string = this.debugForm.value.input?.trim();
    if (!input) {
        return;
    }

    try {
      const bytes = service.base64decode(input);
      this.parseResult = this.parseBytes(bytes);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      this.parseResult = {
        signatureHex: '',
        signatureValid: false,
        dataType: 0,
        dataTypeName: '',
        subtype: 0,
        subtypeName: '',
        version: 0,
        versionName: '',
        totalBytes: 0,
        payloadBytes: 0,
        payloadFields: [],
        error: `Base64 decode failed: ${msg}`,
      };
    }
  }

  private parseBytes(bytes: Uint8Array): ParseResult {
    if (bytes.length < HEADER_SIZE) {
      return this.errorResult(
        bytes.length,
        `Too short: need at least ${HEADER_SIZE} bytes, got ${bytes.length}`
      );
    }

    const signature = readUInt16LE(bytes, 0);
    const signatureValid = signature === SIGNATURE;
    const dataType = readUInt16LE(bytes, 2);
    const subtype = readUInt16LE(bytes, 4);
    const version = readUInt16LE(bytes, 6);

    const subtypeMap = SUBTYPE_NAMES[dataType] ?? {};
    const versionMap = VERSION_NAMES[dataType] ?? {};

    const result: ParseResult = {
      signatureHex: `0x${signature.toString(16).toUpperCase().padStart(4, '0')}`,
      signatureValid,
      dataType,
      dataTypeName: DATA_TYPE_NAMES[dataType] ?? `Unknown (${dataType})`,
      subtype,
      subtypeName: subtypeMap[subtype] ?? `Unknown (${subtype})`,
      version,
      versionName: versionMap[version] ?? `Unknown (${version})`,
      totalBytes: bytes.length,
      payloadBytes: bytes.length - HEADER_SIZE,
      payloadFields: [],
    };

    if (!signatureValid) {
      result.error = `Invalid signature: expected 0x0C0D, got ${result.signatureHex}`;
      return result;
    }

    result.payloadFields = this.parsePayload(bytes, dataType, subtype, version);
    return result;
  }

  private parsePayload(
    bytes: Uint8Array,
    dataType: number,
    subtype: number,
    version: number
  ): PayloadField[] {
    const payload = bytes.slice(HEADER_SIZE);
    const abs = (rel: number) => HEADER_SIZE + rel;

    switch (dataType) {
      case 2:
        return this.parseCiphertextPayload(payload, subtype, version, abs);
      case 1:
        return this.parseKeyPayload(payload, subtype, abs);
      case 3:
        return this.parsePasswordHashPayload(payload, abs);
      case 4:
        return this.parseSharePayload(payload, abs);
      case 8:
        return this.parseDerivationParametersPayload(payload, version, abs);
      default:
        return [
          {
            name: 'Raw Payload',
            offset: HEADER_SIZE,
            size: payload.length,
            hex: toHex(payload, 32),
            description: `${payload.length} bytes — no known structure for this data type`,
          },
        ];
    }
  }

  private parseCiphertextPayload(
    payload: Uint8Array,
    subtype: number,
    version: number,
    abs: (n: number) => number
  ): PayloadField[] {
    const fields: PayloadField[] = [];

    if (version === 1) {
      // V1: IV(16) + Ciphertext(var) + HMAC(32)
      if (payload.length < 48) {
        fields.push({
          name: 'Error',
          offset: abs(0),
          size: payload.length,
          hex: toHex(payload),
          description: `Payload too short for V1 ciphertext (min 48 bytes, got ${payload.length})`,
        });
        return fields;
      }
      const iv = payload.slice(0, 16);
      const ct = payload.slice(16, payload.length - 32);
      const hmac = payload.slice(payload.length - 32);
      fields.push({
        name: 'IV',
        offset: abs(0),
        size: 16,
        hex: toHex(iv),
        description: 'AES-256-CBC Initialization Vector (16 bytes)',
      });
      fields.push({
        name: 'Ciphertext',
        offset: abs(16),
        size: ct.length,
        hex: toHex(ct, 32),
        description: `AES-256-CBC encrypted data with PKCS7 padding (${ct.length} bytes)`,
      });
      fields.push({
        name: 'HMAC-SHA256',
        offset: abs(payload.length - 32),
        size: 32,
        hex: toHex(hmac),
        description: 'Authentication tag over header + IV + ciphertext (32 bytes)',
      });
      return fields;
    }

    // V2 (or Latest/0 which resolves to V2): XChaCha20-Poly1305
    if (subtype === 2) {
      // Asymmetric: EphemeralPubKey(32) + Nonce(24) + Ciphertext+Tag(var)
      if (payload.length < 56) {
        fields.push({
          name: 'Error',
          offset: abs(0),
          size: payload.length,
          hex: toHex(payload),
          description: `Payload too short for V2 asymmetric ciphertext (min 56 bytes, got ${payload.length})`,
        });
        return fields;
      }
      const ephKey = payload.slice(0, 32);
      const nonce = payload.slice(32, 56);
      const ctWithTag = payload.slice(56);
      const ct = ctWithTag.length > 16 ? ctWithTag.slice(0, ctWithTag.length - 16) : new Uint8Array(0);
      const tag = ctWithTag.slice(Math.max(0, ctWithTag.length - 16));
      fields.push({
        name: 'Ephemeral Public Key',
        offset: abs(0),
        size: 32,
        hex: toHex(ephKey),
        description: 'x25519 ephemeral public key for ECDH key derivation (32 bytes)',
      });
      fields.push({
        name: 'Nonce',
        offset: abs(32),
        size: 24,
        hex: toHex(nonce),
        description: 'XChaCha20-Poly1305 nonce (24 bytes)',
      });
      fields.push({
        name: 'Ciphertext',
        offset: abs(56),
        size: ct.length,
        hex: toHex(ct, 32),
        description: `XChaCha20 encrypted data (${ct.length} bytes)`,
      });
      fields.push({
        name: 'Auth Tag (Poly1305)',
        offset: abs(56 + ct.length),
        size: 16,
        hex: toHex(tag),
        description: 'Poly1305 AEAD authentication tag (16 bytes)',
      });
    } else {
      // Symmetric (subtype None=0 or Symmetric=1): Nonce(24) + Ciphertext+Tag(var)
      if (payload.length < 24) {
        fields.push({
          name: 'Error',
          offset: abs(0),
          size: payload.length,
          hex: toHex(payload),
          description: `Payload too short for V2 symmetric ciphertext (min 24 bytes, got ${payload.length})`,
        });
        return fields;
      }
      const nonce = payload.slice(0, 24);
      const ctWithTag = payload.slice(24);
      const ct = ctWithTag.length > 16 ? ctWithTag.slice(0, ctWithTag.length - 16) : new Uint8Array(0);
      const tag = ctWithTag.slice(Math.max(0, ctWithTag.length - 16));
      fields.push({
        name: 'Nonce',
        offset: abs(0),
        size: 24,
        hex: toHex(nonce),
        description: 'XChaCha20-Poly1305 nonce (24 bytes)',
      });
      fields.push({
        name: 'Ciphertext',
        offset: abs(24),
        size: ct.length,
        hex: toHex(ct, 32),
        description: `XChaCha20 encrypted data (${ct.length} bytes)`,
      });
      fields.push({
        name: 'Auth Tag (Poly1305)',
        offset: abs(24 + ct.length),
        size: 16,
        hex: toHex(tag),
        description: 'Poly1305 AEAD authentication tag (16 bytes)',
      });
    }

    return fields;
  }

  private parseKeyPayload(
    payload: Uint8Array,
    subtype: number,
    abs: (n: number) => number
  ): PayloadField[] {
    const label =
      subtype === 1 ? 'Private Key' :
      subtype === 2 ? 'Public Key' :
      subtype === 3 ? 'Key Pair' :
      subtype === 4 ? 'Secret Key' :
      'Key';
    return [
      {
        name: `${label} Bytes`,
        offset: abs(0),
        size: payload.length,
        hex: toHex(payload, 32),
        description: `${label} raw bytes (${payload.length} bytes)`,
      },
    ];
  }

  private parsePasswordHashPayload(
    payload: Uint8Array,
    abs: (n: number) => number
  ): PayloadField[] {
    return [
      {
        name: 'Hash Data',
        offset: abs(0),
        size: payload.length,
        hex: toHex(payload, 32),
        description: `Password hash payload (${payload.length} bytes)`,
      },
    ];
  }

  private parseSharePayload(
    payload: Uint8Array,
    abs: (n: number) => number
  ): PayloadField[] {
    return [
      {
        name: 'Share Data',
        offset: abs(0),
        size: payload.length,
        hex: toHex(payload, 32),
        description: `Secret share payload (${payload.length} bytes)`,
      },
    ];
  }

  private parseDerivationParametersPayload(
    payload: Uint8Array,
    version: number,
    abs: (n: number) => number
  ): PayloadField[] {
    const fields: PayloadField[] = [];
    const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);

    if (version === 1) {
      // V1 PBKDF2: iterations(4 LE u32) + salt_len(4 LE u32) + salt(N bytes)
      if (payload.length < 8) {
        fields.push({
          name: 'Error',
          offset: abs(0),
          size: payload.length,
          hex: toHex(payload),
          description: `Payload too short for V1 derivation parameters (min 8 bytes, got ${payload.length})`,
        });
        return fields;
      }
      const iterations = dv.getUint32(0, true);
      const saltLen = dv.getUint32(4, true);
      const salt = payload.slice(8, 8 + saltLen);
      fields.push({
        name: 'Iterations',
        offset: abs(0),
        size: 4,
        hex: toHex(payload.slice(0, 4)),
        description: `PBKDF2 iteration count: ${iterations.toLocaleString()}`,
      });
      fields.push({
        name: 'Salt Length',
        offset: abs(4),
        size: 4,
        hex: toHex(payload.slice(4, 8)),
        description: `Salt length: ${saltLen} bytes`,
      });
      fields.push({
        name: 'Salt',
        offset: abs(8),
        size: saltLen,
        hex: toHex(salt),
        description: `Random salt for PBKDF2 (${saltLen} bytes)`,
      });
      return fields;
    }

    if (version === 2) {
      // V2 Argon2: Argon2Parameters binary format
      // dc_version(4) + length(4) + lanes(4) + memory(4) + iterations(4) + variant(1) + version(1) + assoc_data_len(4) + assoc_data(N) + salt_len(4) + salt(M)
      if (payload.length < 26) {
        fields.push({
          name: 'Error',
          offset: abs(0),
          size: payload.length,
          hex: toHex(payload),
          description: `Payload too short for V2 derivation parameters (min 26 bytes, got ${payload.length})`,
        });
        return fields;
      }
      let pos = 0;

      const dcVersion = dv.getUint32(pos, true);
      fields.push({
        name: 'DC Version',
        offset: abs(pos),
        size: 4,
        hex: toHex(payload.slice(pos, pos + 4)),
        description: `Devolutions-Crypto Argon2Parameters version: ${dcVersion}`,
      });
      pos += 4;

      const hashLength = dv.getUint32(pos, true);
      fields.push({
        name: 'Hash Length',
        offset: abs(pos),
        size: 4,
        hex: toHex(payload.slice(pos, pos + 4)),
        description: `Argon2 output length: ${hashLength} bytes`,
      });
      pos += 4;

      const lanes = dv.getUint32(pos, true);
      fields.push({
        name: 'Lanes',
        offset: abs(pos),
        size: 4,
        hex: toHex(payload.slice(pos, pos + 4)),
        description: `Argon2 parallelism (lanes): ${lanes}`,
      });
      pos += 4;

      const memory = dv.getUint32(pos, true);
      fields.push({
        name: 'Memory',
        offset: abs(pos),
        size: 4,
        hex: toHex(payload.slice(pos, pos + 4)),
        description: `Argon2 memory usage: ${memory.toLocaleString()} KiB`,
      });
      pos += 4;

      const iterations = dv.getUint32(pos, true);
      fields.push({
        name: 'Iterations',
        offset: abs(pos),
        size: 4,
        hex: toHex(payload.slice(pos, pos + 4)),
        description: `Argon2 time cost (iterations): ${iterations}`,
      });
      pos += 4;

      const variantByte = payload[pos];
      const variantName = variantByte === 0 ? 'Argon2d' : variantByte === 1 ? 'Argon2i' : variantByte === 2 ? 'Argon2id' : `Unknown (${variantByte})`;
      fields.push({
        name: 'Variant',
        offset: abs(pos),
        size: 1,
        hex: toHex(payload.slice(pos, pos + 1)),
        description: `Argon2 variant: ${variantName}`,
      });
      pos += 1;

      const versionByte = payload[pos];
      const versionName = versionByte === 0x13 ? '1.3 (0x13)' : `0x${versionByte.toString(16).padStart(2, '0')}`;
      fields.push({
        name: 'Argon2 Version',
        offset: abs(pos),
        size: 1,
        hex: toHex(payload.slice(pos, pos + 1)),
        description: `Argon2 algorithm version: ${versionName}`,
      });
      pos += 1;

      const assocDataLen = dv.getUint32(pos, true);
      fields.push({
        name: 'Assoc. Data Length',
        offset: abs(pos),
        size: 4,
        hex: toHex(payload.slice(pos, pos + 4)),
        description: `Associated data length: ${assocDataLen} bytes`,
      });
      pos += 4;

      if (assocDataLen > 0) {
        fields.push({
          name: 'Assoc. Data',
          offset: abs(pos),
          size: assocDataLen,
          hex: toHex(payload.slice(pos, pos + assocDataLen)),
          description: `Associated data (${assocDataLen} bytes)`,
        });
        pos += assocDataLen;
      }

      const saltLen = dv.getUint32(pos, true);
      fields.push({
        name: 'Salt Length',
        offset: abs(pos),
        size: 4,
        hex: toHex(payload.slice(pos, pos + 4)),
        description: `Salt length: ${saltLen} bytes`,
      });
      pos += 4;

      const salt = payload.slice(pos, pos + saltLen);
      fields.push({
        name: 'Salt',
        offset: abs(pos),
        size: saltLen,
        hex: toHex(salt),
        description: `Random salt for Argon2 (${saltLen} bytes)`,
      });

      return fields;
    }

    // Unknown version — show raw payload
    return [
      {
        name: 'Raw Payload',
        offset: abs(0),
        size: payload.length,
        hex: toHex(payload, 32),
        description: `${payload.length} bytes — unknown derivation parameters version`,
      },
    ];
  }

  private errorResult(totalBytes: number, message: string): ParseResult {
    return {
      signatureHex: '',
      signatureValid: false,
      dataType: 0,
      dataTypeName: '',
      subtype: 0,
      subtypeName: '',
      version: 0,
      versionName: '',
      totalBytes,
      payloadBytes: 0,
      payloadFields: [],
      error: message,
    };
  }
}
