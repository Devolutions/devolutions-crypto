import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, ReactiveFormsModule } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { FaIconComponent } from '@fortawesome/angular-fontawesome';
import { faSyncAlt } from '@fortawesome/free-solid-svg-icons';
import * as functions from '../shared/shared.component';

import { Argon2Parameters, CiphertextVersion, KeyPair, PrivateKey, PublicKey } from '@devolutions/devolutions-crypto-web';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

@Component({
  selector: 'app-asymmetric',
  standalone: true,
  imports: [ReactiveFormsModule, FaIconComponent],
  templateUrl: './asymmetric.component.html',
})
export class AsymmetricComponent implements OnInit {
  faSyncAlt = faSyncAlt;

  keypairGenerationForm: FormGroup;
  mixKeyForm: FormGroup;
  encryptAsymmetricForm: FormGroup;
  decryptAsymmetricForm: FormGroup;
  argon2Form: FormGroup;

  decoder: TextDecoder;
  encoder: TextEncoder;

  constructor(private encryptionService: EncryptionService) {
    this.decoder = new TextDecoder();
    this.encoder = new TextEncoder();

    this.keypairGenerationForm = new FormGroup({
      generationResult: new FormControl(''),
    });

    this.mixKeyForm = new FormGroup({
      mixPrivateKey: new FormControl(''),
      mixPublicKey: new FormControl(''),
      mixKeyResult: new FormControl('')
    });

    this.encryptAsymmetricForm = new FormGroup({
      textToEncrypt: new FormControl(''),
      publicKeyEncrypt: new FormControl(''),
      encryptVersion: new FormControl(''),
      encryptAsymmetricResult: new FormControl('')
    });

    this.decryptAsymmetricForm = new FormGroup({
      textToDecrypt: new FormControl(''),
      privateKeyDecrypt: new FormControl(''),
      decryptAsymmetricResult: new FormControl('')
    });

    this.argon2Form = new FormGroup({
      argon2Iterations: new FormControl(''),
      argon2Lanes: new FormControl(''),
      argon2Length: new FormControl(''),
      argon2Memory: new FormControl(''),
      argon2Result: new FormControl('')
    });
  }

  ngOnInit() {}

  w3Open() {
    functions.w3_open();
  }

  w3Close() {
    functions.w3_close();
  }

  async createArgon2() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const argon2Iterations: string = this.argon2Form.value.argon2Iterations;
    const argon2Lanes: string = this.argon2Form.value.argon2Lanes;
    const argon2Length: string = this.argon2Form.value.argon2Length;
    const argon2Memory: string = this.argon2Form.value.argon2Memory;

    const parameters: Argon2Parameters = new service.Argon2Parameters();

    if (argon2Iterations) {
      parameters.iterations = Number(argon2Iterations);
    }
    if (argon2Lanes) {
      parameters.lanes = Number(argon2Lanes);
    }
    if (argon2Length) {
      parameters.length = Number(argon2Length);
    }
    if (argon2Memory) {
      parameters.memory = Number(argon2Memory);
    }

    const argon2Result: string = service.base64encode(parameters.bytes);

    this.argon2Form.setValue({
      argon2Iterations,
      argon2Lanes,
      argon2Length,
      argon2Memory,
      argon2Result
    });
  }

  async generateKeypair() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const keypair: KeyPair = service.generateKeyPair(service.KeyVersion.Latest);
    const privateKey: PrivateKey = keypair.private;
    const publicKey: PublicKey = keypair.public;
    if (privateKey === null || publicKey === null) { return; }

    const privateKeyText: string = service.base64encode(privateKey.bytes);
    const publicKeyText: string = service.base64encode(publicKey.bytes);
    const text = `Private key: ${privateKeyText}\n\nPublic key: ${publicKeyText}`;

    this.keypairGenerationForm.setValue({ generationResult: text });
  }

  async mixKeys() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const privateKeyString: string = this.mixKeyForm.value.mixPrivateKey;
    const publicKeyString: string = this.mixKeyForm.value.mixPublicKey;
    if (privateKeyString === null || privateKeyString === '' ||
        publicKeyString === null || publicKeyString === '') { return; }

    const privateKeyArray: Uint8Array = service.base64decode(privateKeyString.trim());
    const publicKeyArray: Uint8Array = service.base64decode(publicKeyString.trim());
    const privateKey: PrivateKey = service.PrivateKey.fromBytes(privateKeyArray);
    const publicKey: PublicKey = service.PublicKey.fromBytes(publicKeyArray);

    const mixKey = service.mixKeyExchange(privateKey, publicKey);
    const mixKeyEncoded = service.base64encode(mixKey);

    this.mixKeyForm.setValue({
      mixPrivateKey: privateKeyString,
      mixPublicKey: publicKeyString,
      mixKeyResult: mixKeyEncoded
    });
  }

  async encryptAsymmetric() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const textToEncrypt: string = this.encryptAsymmetricForm.value.textToEncrypt;
    const publicKeyEncrypt: string = this.encryptAsymmetricForm.value.publicKeyEncrypt;
    if (textToEncrypt === null || textToEncrypt === '' ||
        publicKeyEncrypt === null || publicKeyEncrypt === '') { return; }

    const publicKeyArray: Uint8Array = service.base64decode(publicKeyEncrypt.trim());
    const publicKey: PublicKey = service.PublicKey.fromBytes(publicKeyArray);
    const textToEncryptArray: Uint8Array = this.encoder.encode(textToEncrypt);

    const version: CiphertextVersion = service.CiphertextVersion.Latest;
    const encryptedText: Uint8Array = service.encryptAsymmetric(textToEncryptArray, publicKey, version);

    this.encryptAsymmetricForm.setValue({
      textToEncrypt,
      publicKeyEncrypt,
      encryptVersion: '',
      encryptAsymmetricResult: service.base64encode(encryptedText)
    });
  }

  async decryptAsymmetric() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const textToDecrypt: string = this.decryptAsymmetricForm.value.textToDecrypt;
    const privateKeyDecrypt: string = this.decryptAsymmetricForm.value.privateKeyDecrypt;
    if (textToDecrypt === null || textToDecrypt === '' ||
        privateKeyDecrypt === null || privateKeyDecrypt === '') { return; }

    const privateKeyArray: Uint8Array = service.base64decode(privateKeyDecrypt.trim());
    const privateKey: PrivateKey = service.PrivateKey.fromBytes(privateKeyArray);
    const textToDecryptArray: Uint8Array = service.base64decode(textToDecrypt.trim());

    const decryptedText: Uint8Array = service.decryptAsymmetric(textToDecryptArray, privateKey);
    const text: string = this.decoder.decode(decryptedText);

    this.decryptAsymmetricForm.setValue({
      textToDecrypt,
      privateKeyDecrypt,
      decryptAsymmetricResult: text
    });
  }
}
