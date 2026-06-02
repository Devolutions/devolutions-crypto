import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, ReactiveFormsModule } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { FaIconComponent } from '@fortawesome/angular-fontawesome';
import { faShieldHalved } from '@fortawesome/free-solid-svg-icons';
import * as functions from '../shared/shared.component';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

@Component({
  selector: 'app-derive-encrypt',
  standalone: true,
  imports: [ReactiveFormsModule, FaIconComponent],
  templateUrl: './derive-encrypt.component.html',
})
export class DeriveEncryptComponent implements OnInit {
  faShieldHalved = faShieldHalved;

  algorithm: 'argon2' | 'pbkdf2' = 'argon2';
  cipherAlgorithm: 'xchacha20' | 'aes' = 'xchacha20';

  encryptForm: FormGroup;
  decryptForm: FormGroup;

  encoder: TextEncoder;
  decoder: TextDecoder;

  constructor(private encryptionService: EncryptionService) {
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder();

    this.encryptForm = new FormGroup({
      plaintext: new FormControl(''),
      password: new FormControl(''),
      aad: new FormControl(''),
      // Argon2 params
      argon2Memory: new FormControl(''),
      argon2Iterations: new FormControl(''),
      argon2Lanes: new FormControl(''),
      // PBKDF2 params
      pbkdf2Iterations: new FormControl(''),
      pbkdf2Salt: new FormControl(''),
      // Output
      encryptResult: new FormControl(''),
    });

    this.decryptForm = new FormGroup({
      ciphertext: new FormControl(''),
      password: new FormControl(''),
      aad: new FormControl(''),
      decryptResult: new FormControl(''),
    });
  }

  ngOnInit() {}

  setAlgorithm(algo: 'argon2' | 'pbkdf2') {
    this.algorithm = algo;
    this.encryptForm.patchValue({ encryptResult: '' });
  }

  setCipherAlgorithm(cipher: 'xchacha20' | 'aes') {
    this.cipherAlgorithm = cipher;
    this.encryptForm.patchValue({ encryptResult: '' });
  }

  w3Open() { functions.w3_open(); }
  w3Close() { functions.w3_close(); }

  async encrypt() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const plaintext: string = this.encryptForm.value.plaintext;
    const password: string = this.encryptForm.value.password;
    if (!plaintext || !password) { return; }

    const plaintextBytes = this.encoder.encode(plaintext);
    const passwordBytes = this.encoder.encode(password);
    const aadStr: string = this.encryptForm.value.aad;
    const aad: Uint8Array | undefined = aadStr ? this.encoder.encode(aadStr) : undefined;

    try {
      let params: import('@devolutions/devolutions-crypto-web').DerivationParameters | undefined;

      if (this.algorithm === 'argon2') {
        const argon2Params = new service.Argon2Parameters();
        const memory: string = this.encryptForm.value.argon2Memory;
        const iterations: string = this.encryptForm.value.argon2Iterations;
        const lanes: string = this.encryptForm.value.argon2Lanes;
        if (memory) { argon2Params.memory = Number(memory); }
        if (iterations) { argon2Params.iterations = Number(iterations); }
        if (lanes) { argon2Params.lanes = Number(lanes); }
        params = service.deriveSecretKeyArgon2(passwordBytes, argon2Params).parameters;
      } else {
        const iterStr: string = this.encryptForm.value.pbkdf2Iterations;
        const saltStr: string = this.encryptForm.value.pbkdf2Salt;
        const iterations: number | undefined = iterStr ? Number(iterStr) : undefined;
        let kdfResult;
        if (saltStr) {
          kdfResult = service.deriveSecretKeyPbkdf2WithSalt(passwordBytes, this.encoder.encode(saltStr), iterations);
        } else {
          kdfResult = service.deriveSecretKeyPbkdf2(passwordBytes, iterations);
        }
        params = kdfResult.parameters;
      }

      const version = this.cipherAlgorithm === 'aes' ? service.CiphertextVersion.V1 : service.CiphertextVersion.V2;
      const blob = service.deriveEncryptWithPassword(plaintextBytes, passwordBytes, aad, params, version);
      this.encryptForm.patchValue({ encryptResult: service.base64encode(blob) });
    } catch (e: any) {
      this.encryptForm.patchValue({ encryptResult: `Error: ${e?.message ?? e}` });
    }
  }

  async decrypt() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const ciphertextStr: string = this.decryptForm.value.ciphertext;
    const password: string = this.decryptForm.value.password;
    if (!ciphertextStr || !password) { return; }

    const passwordBytes = this.encoder.encode(password);
    const aadStr: string = this.decryptForm.value.aad;
    const aad: Uint8Array | undefined = aadStr ? this.encoder.encode(aadStr) : undefined;

    try {
      const blob = service.base64decode(ciphertextStr.trim());
      const plaintext = service.deriveDecryptWithPassword(blob, passwordBytes, aad);
      this.decryptForm.patchValue({ decryptResult: this.decoder.decode(plaintext) });
    } catch (e: any) {
      this.decryptForm.patchValue({ decryptResult: `Error: ${e?.message ?? e}` });
    }
  }
}
