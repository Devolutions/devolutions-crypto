import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl } from '@angular/forms';
import { EncryptionService } from '../service/encryption.service';
import { faUserSecret } from '@fortawesome/free-solid-svg-icons';
import * as functions from '../shared/shared.component';

type EncryptionServiceInner = typeof import('../service/encryption.inner.service');

@Component({
  selector: 'app-shamir',
  templateUrl: './secret-sharing.component.html',
  providers: [EncryptionService]
})
export class SecretSharingComponent implements OnInit {
  faUserSecret = faUserSecret;
  generateSharesForm: FormGroup;
  nbShares: FormControl;
  threshold: FormControl;
  secretLength: FormControl;

  generatedKeysBase64: string[];
  joinnedSharesToShow: string[];
  joinnedShares: Uint8Array[];

  joinSharesForm: FormGroup;
  addSharekey: FormControl;
  joinResult: FormControl;

  decoder: TextDecoder;
  encoder: TextEncoder;

  constructor(private encryptionService: EncryptionService) {
    this.decoder = new TextDecoder();
    this.encoder = new TextEncoder();

    this.joinnedShares = [];
    this.joinnedSharesToShow = [];

    this.generateSharesForm = new FormGroup({
      nbShares: new FormControl(''),
      threshold: new FormControl(''),
      secretLength: new FormControl('')
    });

    this.joinSharesForm = new FormGroup({
      addSharekey: new FormControl(''),
      joinResult: new FormControl('')
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

  async generateShares() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const nbShares: string = this.generateSharesForm.value.nbShares;
    const threshold: string = this.generateSharesForm.value.threshold;
    const secretLengthString: string = this.generateSharesForm.value.secretLength;
    if (nbShares === null || nbShares === '' || threshold === null || threshold === '') { return; }

    const secretLength: number =  (secretLengthString === null || secretLengthString === '') ? null : Number(secretLengthString);
    const generatedKeys: Uint8Array[] = service.generateSharedKey(Number(nbShares), Number(threshold), secretLength);

    // Encode the shares
    if (generatedKeys != null && generatedKeys.length > 0) {
      this.generatedKeysBase64 = [];
      generatedKeys.forEach(element => {
        const base64Text: string = service.base64encode(element);
        this.generatedKeysBase64.push(base64Text.trim());
      });
    }
  }

  async addShare() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    const shareBase64: string = this.joinSharesForm.value.addSharekey;
    if (shareBase64 === null || shareBase64 === '') { return; }

    // Ensure this is valid base64 and add them to the list
    const share: Uint8Array = service.base64decode(shareBase64.trim());
    this.joinnedSharesToShow.push(shareBase64);
    this.joinnedShares.push(share);

    const addResult = {
      addSharekey: '',
      joinResult: ''
    };
    this.joinSharesForm.setValue(addResult);
  }

  async joinShares() {
    // Await the service initialization
    const service: EncryptionServiceInner = await this.encryptionService.innerModule;

    if (this.joinnedShares === null || this.joinnedShares.length === 0) { return; }

    const key: Uint8Array = service.joinShares(this.joinnedShares);

    const keyBase64: string = service.base64encode(key);
    const joinResult = {
      addSharekey: '',
      joinResult: keyBase64
    };

    this.joinSharesForm.setValue(joinResult);
  }

}
