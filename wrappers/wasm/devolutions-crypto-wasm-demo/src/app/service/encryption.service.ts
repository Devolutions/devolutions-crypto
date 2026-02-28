import { Injectable } from '@angular/core';

type EncryptionServiceInner = typeof import('./encryption.inner.service');

@Injectable({
  providedIn: 'root',
})
export class EncryptionService {
  public innerModule: Promise<EncryptionServiceInner>;
  constructor() {
    this.innerModule = import('./encryption.inner.service').then((mod) => mod);
  }
}
