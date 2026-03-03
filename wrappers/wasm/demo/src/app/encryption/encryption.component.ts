import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, ReactiveFormsModule } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { FaIconComponent } from '@fortawesome/angular-fontawesome';
import { faEyeSlash } from '@fortawesome/free-solid-svg-icons';
import * as functions from '../shared/shared.component';

import { CiphertextVersion } from '@devolutions/devolutions-crypto-web';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

@Component({
  selector: 'app-encryption',
  standalone: true,
  imports: [ReactiveFormsModule, FaIconComponent],
  templateUrl: './encryption.component.html',
})
export class EncryptionComponent implements OnInit {
  faEyeSlash = faEyeSlash;
  encryptionForm: FormGroup;
  decryptionForm: FormGroup;

  decoder: TextDecoder;
  encoder: TextEncoder;

  constructor(private encryptionService: EncryptionService) {
    this.decoder = new TextDecoder();
    this.encoder = new TextEncoder();

    this.encryptionForm = new FormGroup({
      encryptResult: new FormControl(''),
      encryptText: new FormControl(''),
      encryptPassword: new FormControl(''),
      encryptSalt: new FormControl(''),
    });
    this.decryptionForm = new FormGroup({
      encryptedText: new FormControl(''),
      decryptResult: new FormControl(''),
      decryptPassword: new FormControl(''),
      decryptSalt: new FormControl('')
    });
  }

  ngOnInit() {}

  w3Open() {
    functions.w3_open();
  }

  w3Close() {
    functions.w3_close();
  }

  async encrypt() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const text: string = this.encryptionForm.value.encryptText;
    const pwd: string = this.encryptionForm.value.encryptPassword;
    const salt: string = this.encryptionForm.value.encryptSalt;
    if (text === null || text === '' || pwd === null || pwd === '') { return; }

    const pwdArray: Uint8Array = this.encoder.encode(pwd);
    const saltArray: Uint8Array | undefined = (salt === null || salt === '') ? undefined : this.encoder.encode(salt);
    const data: Uint8Array = this.encoder.encode(text);

    const version: CiphertextVersion = service.CiphertextVersion.Latest;
    const key: Uint8Array = service.deriveKeyPbkdf2(pwdArray, saltArray);
    const ciphertext: Uint8Array = service.encrypt(data, key, version);

    this.encryptionForm.setValue({
      encryptText: text,
      encryptPassword: pwd,
      encryptSalt: salt,
      encryptResult: service.base64encode(ciphertext)
    });
  }

  async decrypt() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const encryptedText: string = this.decryptionForm.value.encryptedText;
    const pwd: string = this.decryptionForm.value.decryptPassword;
    const salt: string = this.decryptionForm.value.decryptSalt;
    if (encryptedText === null || encryptedText === '' || pwd === null || pwd === '') { return; }

    const pwdArray: Uint8Array = this.encoder.encode(pwd);
    const saltArray: Uint8Array | undefined = (salt === null || salt === '') ? undefined : this.encoder.encode(salt);

    const key: Uint8Array = service.deriveKeyPbkdf2(pwdArray, saltArray);
    const ciphertext: Uint8Array = service.base64decode(encryptedText.trim());
    const plaintext: Uint8Array = service.decrypt(ciphertext, key);
    const text: string = this.decoder.decode(plaintext);

    this.decryptionForm.setValue({
      encryptedText,
      decryptPassword: pwd,
      decryptSalt: salt,
      decryptResult: text
    });
  }
}
