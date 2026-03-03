import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, ReactiveFormsModule } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { FaIconComponent } from '@fortawesome/angular-fontawesome';
import { faTools } from '@fortawesome/free-solid-svg-icons';
import * as functions from '../shared/shared.component';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

@Component({
  selector: 'app-utilities',
  standalone: true,
  imports: [ReactiveFormsModule, FaIconComponent],
  templateUrl: './utilities.component.html',
})
export class UtilitiesComponent implements OnInit {
  faTools = faTools;
  keyGenerationForm: FormGroup;
  deriveKeyForm: FormGroup;
  encodeDecodeForm: FormGroup;

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

  ngOnInit() {}

  w3Open() {
    functions.w3_open();
  }

  w3Close() {
    functions.w3_close();
  }

  async encode() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const toEncode: string = this.encodeDecodeForm.value.enDecodeText;
    if (toEncode === null || toEncode === '') { return; }

    const encodedText: string = service.base64encode(this.encoder.encode(toEncode));

    this.encodeDecodeForm.setValue({
      enDecodeText: toEncode,
      enDecodeResult: encodedText
    });
  }

  async decode() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const toDecode: string = this.encodeDecodeForm.value.enDecodeText;
    if (toDecode === null || toDecode === '') { return; }

    const decodedText: string = this.decoder.decode(service.base64decode(toDecode.trim()));

    this.encodeDecodeForm.setValue({
      enDecodeText: toDecode,
      enDecodeResult: decodedText
    });
  }

  async generateKey() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const key: Uint8Array = service.generateKey();

    this.keyGenerationForm.setValue({
      generationResult: service.base64encode(key)
    });
  }

  async deriveKey() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const derivePassword: string = this.deriveKeyForm.value.derivePassword;
    const deriveSalt: string = this.deriveKeyForm.value.deriveSalt;
    const deriveIterationsString: string = this.deriveKeyForm.value.deriveIterations;
    const deriveLengthString: string = this.deriveKeyForm.value.deriveLength;
    if (derivePassword === null || derivePassword === '') { return; }

    const derivePasswordArray: Uint8Array = this.encoder.encode(derivePassword);
    const deriveSaltArray: Uint8Array | undefined = (deriveSalt === null || deriveSalt === '')
      ? undefined : this.encoder.encode(deriveSalt);
    const deriveLength: number | undefined = (deriveLengthString === null || deriveLengthString === '')
      ? undefined : Number(deriveLengthString);
    const deriveIterations: number | undefined = (deriveIterationsString === null || deriveIterationsString === '')
      ? undefined : Number(deriveIterationsString);

    const derivedKey: Uint8Array = service.deriveKeyPbkdf2(derivePasswordArray, deriveSaltArray, deriveIterations, deriveLength);
    if (derivedKey === null) { return; }
    const derivedKeyText: string = service.base64encode(derivedKey);

    this.deriveKeyForm.setValue({
      derivePassword,
      deriveSalt,
      deriveIterations: deriveIterationsString,
      deriveLength: deriveLengthString,
      deriveResult: derivedKeyText
    });
  }
}
