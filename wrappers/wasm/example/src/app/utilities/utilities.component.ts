import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { faTools } from '@fortawesome/free-solid-svg-icons';
import * as functions from '../shared/shared.component';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

@Component({
  selector: 'app-utilities',
  templateUrl: './utilities.component.html',
  styleUrls: ['./utilities.component.styl']
})
export class UtilitiesComponent implements OnInit {
  faTools = faTools;
  keyGenerationForm: FormGroup;
  generationResult: FormControl;

  deriveKeyForm: FormGroup;
  derivePassword: FormControl;
  deriveSalt: FormControl;
  deriveIterations: FormControl;
  deriveLength: FormControl;
  deriveResult: FormControl;

  encodeDecodeForm: FormGroup;
  enDecodeText: FormControl;
  enDecodeResult: FormControl;

  decoder: TextDecoder;
  encoder: TextEncoder;

  constructor(private encryptionService: EncryptionService) {
    this.decoder = new TextDecoder();
    this.encoder = new TextEncoder();

    this.keyGenerationForm = new FormGroup({
      generationResult: new FormControl(''),
    });

    this.encodeDecodeForm = new FormGroup({
      enDecodeText: new FormControl(''),
      enDecodeResult: new FormControl('')
    });

    this.deriveKeyForm = new FormGroup({
      derivePassword: new FormControl(''),
      deriveSalt: new FormControl(''),
      deriveIterations: new FormControl(''),
      deriveLength: new FormControl(''),
      deriveResult: new FormControl('')
    });

   }

  w3Open() {
    functions.w3_open();
  }

  w3Close() {
    functions.w3_close();
  }

  ngOnInit() {
  }

  async encode() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const toEncode: string = this.encodeDecodeForm.value.en_decodeText;
    if (toEncode === null || toEncode === '') { return; }

    const encodedText: string = service.base64encode(this.encoder.encode(toEncode));

    const result = {
      en_decodeText: toEncode,
      en_decodeResult: encodedText
    };

    this.encodeDecodeForm.setValue(result);
  }

  async decode() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const toDecode: string = this.encodeDecodeForm.value.en_decodeText;
    if (toDecode === null || toDecode === '') { return; }

    const decodedText: string = this.decoder.decode(service.base64decode(toDecode.trim()));
    const result = {
      en_decodeText: toDecode,
      en_decodeResult: decodedText
    };

    this.encodeDecodeForm.setValue(result);
  }

  async generateKey() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const key: Uint8Array = service.generateKey();

    const result = {
      generationResult: service.base64encode(key)
    };

    this.keyGenerationForm.setValue(result);
  }



  async deriveKey() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const derivePassword: string = this.deriveKeyForm.value.derivePassword;
    const deriveSalt: string = this.deriveKeyForm.value.deriveSalt;
    const deriveIterationsString: string = this.deriveKeyForm.value.deriveIterations;
    const deriveLengthString: string = this.deriveKeyForm.value.deriveLength;
    if (derivePassword === null || derivePassword === '') { return; }

    const derivePasswordArray: Uint8Array = this.encoder.encode(derivePassword);
    const deriveSaltArray: Uint8Array = (deriveSalt === null || deriveSalt === '')
                                        ? null : this.encoder.encode(deriveSalt);
    const deriveLength: number = (deriveLengthString === null || deriveLengthString === '')
                                  ? null : Number(deriveLengthString);
    const deriveIterations: number = (deriveIterationsString === null || deriveIterationsString === '')
                                      ? null : Number(deriveIterationsString);

    const derivedKey: Uint8Array = service.deriveKeyPbkdf2(derivePasswordArray, deriveSaltArray, deriveIterations, deriveLength);
    if (derivedKey === null) { return; }
    const derivedKeyText: string = service.base64encode(derivedKey);

    const result = {
      derivePassword,
      deriveSalt,
      deriveIterations: deriveIterationsString,
      deriveLength: deriveLengthString,
      deriveResult: derivedKeyText
    };

    this.deriveKeyForm.setValue(result);
  }
}
