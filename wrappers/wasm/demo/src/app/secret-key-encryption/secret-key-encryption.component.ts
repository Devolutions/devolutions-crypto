import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, ReactiveFormsModule } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { FaIconComponent } from '@fortawesome/angular-fontawesome';
import { faKey } from '@fortawesome/free-solid-svg-icons';
import * as functions from '../shared/shared.component';

import { CiphertextVersion, KeyVersion, SecretKey } from '@devolutions/devolutions-crypto-web';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

@Component({
  selector: 'app-secret-key-encryption',
  standalone: true,
  imports: [ReactiveFormsModule, FaIconComponent],
  templateUrl: './secret-key-encryption.component.html',
})
export class SecretKeyEncryptionComponent implements OnInit {
  faKey = faKey;

  keyGenerationForm: FormGroup;
  encryptForm: FormGroup;
  decryptForm: FormGroup;

  decoder: TextDecoder;
  encoder: TextEncoder;

  constructor(private encryptionService: EncryptionService) {
    this.decoder = new TextDecoder();
    this.encoder = new TextEncoder();

    this.keyGenerationForm = new FormGroup({
      generationResult: new FormControl(''),
    });

    this.encryptForm = new FormGroup({
      textToEncrypt: new FormControl(''),
      secretKey: new FormControl(''),
      encryptResult: new FormControl(''),
    });

    this.decryptForm = new FormGroup({
      textToDecrypt: new FormControl(''),
      secretKey: new FormControl(''),
      decryptResult: new FormControl(''),
    });
  }

  ngOnInit() {}

  w3Open() {
    functions.w3_open();
  }

  w3Close() {
    functions.w3_close();
  }

  async generateSecretKey() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const key: SecretKey = service.generateSecretKey(service.KeyVersion.Latest);
    const keyText: string = service.base64encode(key.bytes);

    this.keyGenerationForm.setValue({ generationResult: keyText });
  }

  async encrypt() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const textToEncrypt: string = this.encryptForm.value.textToEncrypt;
    const secretKeyString: string = this.encryptForm.value.secretKey;
    if (!textToEncrypt || !secretKeyString) { return; }

    const keyBytes: Uint8Array = service.base64decode(secretKeyString.trim());
    const key: SecretKey = service.SecretKey.fromBytes(keyBytes);
    const data: Uint8Array = this.encoder.encode(textToEncrypt);

    const version: CiphertextVersion = service.CiphertextVersion.Latest;
    const encrypted: Uint8Array = service.encryptWithSecretKey(data, key, version);

    this.encryptForm.setValue({
      textToEncrypt,
      secretKey: secretKeyString,
      encryptResult: service.base64encode(encrypted),
    });
  }

  async decrypt() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const textToDecrypt: string = this.decryptForm.value.textToDecrypt;
    const secretKeyString: string = this.decryptForm.value.secretKey;
    if (!textToDecrypt || !secretKeyString) { return; }

    const keyBytes: Uint8Array = service.base64decode(secretKeyString.trim());
    const key: SecretKey = service.SecretKey.fromBytes(keyBytes);
    const ciphertext: Uint8Array = service.base64decode(textToDecrypt.trim());

    const plaintext: Uint8Array = service.decryptWithSecretKey(ciphertext, key);
    const text: string = this.decoder.decode(plaintext);

    this.decryptForm.setValue({
      textToDecrypt,
      secretKey: secretKeyString,
      decryptResult: text,
    });
  }
}
