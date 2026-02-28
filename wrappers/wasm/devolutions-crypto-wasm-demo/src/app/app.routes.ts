import { Routes } from '@angular/router';
import { EncryptionComponent } from './encryption/encryption.component';
import { SecretSharingComponent } from './secret-sharing/secret-sharing.component';
import { PasswordComponent } from './password/password.component';
import { UtilitiesComponent } from './utilities/utilities.component';
import { AsymmetricComponent } from './asymmetric/asymmetric.component';

export const routes: Routes = [
  { path: '', redirectTo: '/encryption', pathMatch: 'full' },
  { path: 'encryption', component: EncryptionComponent },
  { path: 'secret-sharing', component: SecretSharingComponent },
  { path: 'password', component: PasswordComponent },
  { path: 'utilities', component: UtilitiesComponent },
  { path: 'asymmetric', component: AsymmetricComponent }
];
