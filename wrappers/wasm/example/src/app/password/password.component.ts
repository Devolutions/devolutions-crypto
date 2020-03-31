import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { faKey } from '@fortawesome/free-solid-svg-icons';
import * as functions from '../shared/shared.component';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

@Component({
  selector: 'app-utils',
  templateUrl: './password.component.html',
  styleUrls: ['./password.component.styl']
})
export class PasswordComponent implements OnInit {
  faKey = faKey;
  passwordForm: FormGroup;
  password: FormControl;
  iteration: FormControl;
  hashResult: FormControl;

  verifyForm: FormGroup;
  passwordResult: FormControl;
  passwordV: FormControl;
  hashV: FormControl;

  decoder: TextDecoder;
  encoder: TextEncoder;

  constructor(private encryptionService: EncryptionService) {
    this.decoder = new TextDecoder();
    this.encoder = new TextEncoder();

    this.passwordForm = new FormGroup({
      password: new FormControl(''),
      iteration: new FormControl(''),
      hashResult: new FormControl('')
    });

    this.verifyForm = new FormGroup({
      passwordV: new FormControl(''),
      hashV: new FormControl(''),
      passwordResult: new FormControl('')
    });
   }

  w3Open() {
    functions.w3_open();
  }

  w3Close() {
    functions.w3_close();
  }

  async hash() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const pwd: string = this.passwordForm.value.password;
    const iterString: string = this.passwordForm.value.iteration;
    if (pwd === null || pwd === '') { return; }

    const pwdArray: Uint8Array = this.encoder.encode(pwd);
    const iter: number =  (iterString === null || iterString === '') ? null : Number(iterString);

    const hash: Uint8Array = service.hashPassword(pwdArray, iter, service.CiphertextVersion.Latest);
    const hashBase64: string = service.base64encode(hash);

    const result = {
      password: pwd,
      iteration: iter,
      hashResult: hashBase64
    };

    this.passwordForm.setValue(result);
  }

  async verify() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const pwd: string = this.verifyForm.value.passwordV;
    const hash: string = this.verifyForm.value.hashV;
    if (pwd === null || pwd === '' || hash === null || hash === '') { return; }

    const pwdArray: Uint8Array = this.encoder.encode(pwd);
    const hashArray: Uint8Array = service.base64decode(hash.trim());
    const passwordR: boolean = service.verifyPassword(pwdArray, hashArray);

    const result = {
      passwordV: pwd,
      hashV: hash,
      passwordResult: passwordR === true ? 'Verified' : 'Not verified'
    };

    this.verifyForm.setValue(result);

  }

  ngOnInit() {

  }
}
