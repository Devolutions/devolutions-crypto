import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, ReactiveFormsModule } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { FaIconComponent } from '@fortawesome/angular-fontawesome';
import { faKey } from '@fortawesome/free-solid-svg-icons';
import { NgIf } from '@angular/common';
import * as functions from '../shared/shared.component';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

@Component({
  selector: 'app-key-derivation',
  standalone: true,
  imports: [ReactiveFormsModule, FaIconComponent, NgIf],
  templateUrl: './key-derivation.component.html',
})
export class KeyDerivationComponent implements OnInit {
  faKey = faKey;

  algorithm: 'argon2' | 'pbkdf2' = 'argon2';

  deriveForm: FormGroup;

  encoder: TextEncoder;

  constructor(private encryptionService: EncryptionService) {
    this.encoder = new TextEncoder();

    this.deriveForm = new FormGroup({
      password: new FormControl(''),
      // Argon2 parameters
      argon2Memory: new FormControl(''),
      argon2Iterations: new FormControl(''),
      argon2Lanes: new FormControl(''),
      // PBKDF2 parameters
      pbkdf2Iterations: new FormControl(''),
      pbkdf2Salt: new FormControl(''),
      // Outputs
      secretKeyResult: new FormControl(''),
      parametersResult: new FormControl(''),
    });
  }

  ngOnInit() {}

  setAlgorithm(algo: 'argon2' | 'pbkdf2') {
    this.algorithm = algo;
    this.deriveForm.patchValue({ secretKeyResult: '', parametersResult: '' });
  }

  w3Open() { functions.w3_open(); }
  w3Close() { functions.w3_close(); }

  async derive() {
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const password: string = this.deriveForm.value.password;
    if (!password) { return; }

    const passwordBytes: Uint8Array = this.encoder.encode(password);

    try {
      if (this.algorithm === 'argon2') {
        const params = new service.Argon2Parameters();

        const memory: string = this.deriveForm.value.argon2Memory;
        const iterations: string = this.deriveForm.value.argon2Iterations;
        const lanes: string = this.deriveForm.value.argon2Lanes;

        if (memory) { params.memory = Number(memory); }
        if (iterations) { params.iterations = Number(iterations); }
        if (lanes) { params.lanes = Number(lanes); }

        const result = service.deriveSecretKeyArgon2(passwordBytes, params);

        this.deriveForm.patchValue({
          secretKeyResult: service.base64encode(result.secretKey.bytes),
          parametersResult: service.base64encode(result.parameters.bytes),
        });
      } else {
        const iterStr: string = this.deriveForm.value.pbkdf2Iterations;
        const saltStr: string = this.deriveForm.value.pbkdf2Salt;

        const iterations: number | undefined = iterStr ? Number(iterStr) : undefined;
        const salt: Uint8Array | undefined = saltStr ? this.encoder.encode(saltStr) : undefined;

        // PBKDF2 uses a random salt unless one is embedded via derive_with_salt (not directly exposed to WASM).
        // We call deriveSecretKeyPbkdf2 with the requested iterations; salt is always random on this path.
        // If a custom salt was provided, inform the user it is not used on this path.
        const result = service.deriveSecretKeyPbkdf2(passwordBytes, iterations);

        this.deriveForm.patchValue({
          secretKeyResult: service.base64encode(result.secretKey.bytes),
          parametersResult: service.base64encode(result.parameters.bytes),
        });
      }
    } catch (e: any) {
      this.deriveForm.patchValue({
        secretKeyResult: `Error: ${e?.message ?? e}`,
        parametersResult: '',
      });
    }
  }
}
