import { Routes } from '@angular/router';
import { EncryptionComponent } from './encryption/encryption.component';
import { SecretSharingComponent } from './secret-sharing/secret-sharing.component';
import { PasswordComponent } from './password/password.component';
import { UtilitiesComponent } from './utilities/utilities.component';
import { AsymmetricComponent } from './asymmetric/asymmetric.component';
import { SecretKeyEncryptionComponent } from './secret-key-encryption/secret-key-encryption.component';
import { InspectComponent } from './inspect/inspect.component';
import { KeyDerivationComponent } from './key-derivation/key-derivation.component';
import { DeriveEncryptComponent } from './derive-encrypt/derive-encrypt.component';

export const routes: Routes = [
  { path: '', redirectTo: '/encryption', pathMatch: 'full' },
  { path: 'encryption', component: EncryptionComponent },
  { path: 'secret-sharing', component: SecretSharingComponent },
  { path: 'password', component: PasswordComponent },
  { path: 'key-derivation', component: KeyDerivationComponent },
  { path: 'derive-encrypt', component: DeriveEncryptComponent },
  { path: 'utilities', component: UtilitiesComponent },
  { path: 'asymmetric', component: AsymmetricComponent },
  { path: 'secret-key-encryption', component: SecretKeyEncryptionComponent },
  { path: 'inspect', component: InspectComponent }
];
