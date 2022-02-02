import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { faEyeSlash } from '@fortawesome/free-solid-svg-icons';
import * as functions from '../shared/shared.component';

import { CiphertextVersion } from '@devolutions/devolutions-crypto';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

@Component({
  selector: 'app-encryption',
  templateUrl: './encryption.component.html',
  styleUrls: ['./encryption.component.styl'],
  providers: [EncryptionService]
})
export class EncryptionComponent implements OnInit {
  faEyeSlash = faEyeSlash;
  encryptionForm: FormGroup;
  decryptionForm: FormGroup;

  encryptResult: FormControl;
  encryptText: FormControl;
  encryptPassword: FormControl;
  encryptSalt: FormControl;

  encryptedText: FormControl;
  decryptResult: FormControl;
  decryptPassword: FormControl;
  decryptSalt: FormControl;

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

  ngOnInit() {

  }

  w3Open() {
    functions.w3_open();
  }

  w3Close() {
    functions.w3_close();
  }

  async encrypt() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const text: string = this.encryptionForm.value.encryptText;
    const pwd: string = this.encryptionForm.value.encryptPassword;
    const salt: string = this.encryptionForm.value.encryptSalt;
    if (text === null || text === '' ||
        pwd === null || pwd === '') { return; }

    const pwdArray: Uint8Array = this.encoder.encode(pwd);
    const saltArray: Uint8Array = (salt === null || salt === '') ? null : this.encoder.encode(salt);
    const data: Uint8Array = this.encoder.encode(text);

    // You can use the types directly, but you must use the service to use their functions
    const version: CiphertextVersion = service.CiphertextVersion.Latest;

    const key: Uint8Array = service.deriveKeyPbkdf2(pwdArray, saltArray);
    const ciphertext: Uint8Array = service.encrypt(data, key, version);

    const encrypt = {
      encryptText: text,
      encryptPassword: pwd,
      encryptSalt: salt,
      encryptResult: service.base64encode(ciphertext)
    };

    this.encryptionForm.setValue(encrypt);
  }

  async decrypt() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const encryptedText: string = this.decryptionForm.value.encryptedText;
    const pwd: string = this.decryptionForm.value.decryptPassword;
    const salt: string = this.decryptionForm.value.decryptSalt;
    if (encryptedText === null || encryptedText === '' ||
        pwd === null || pwd === '') { return; }

    const pwdArray: Uint8Array = this.encoder.encode(pwd);
    const saltArray: Uint8Array = (salt === null || salt === '') ? null : this.encoder.encode(salt);

    const key: Uint8Array = service.deriveKeyPbkdf2(pwdArray, saltArray);
    const ciphertext: Uint8Array = service.base64decode(encryptedText.trim());
    const plaintext: Uint8Array = service.decrypt(ciphertext, key);
    const text: string = this.decoder.decode(plaintext);

    const decrypt = {
      encryptedText,
      decryptPassword: pwd,
      decryptSalt: salt,
      decryptResult: text
    };

    this.decryptionForm.setValue(decrypt);

  }
}
