import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { SecretSharingComponent } from './secret-sharing/secret-sharing.component';
import { PasswordComponent } from './password/password.component';
import { EncryptionComponent } from './encryption/encryption.component';
import { UtilitiesComponent } from './utilities/utilities.component';
import { AsymmetricComponent } from './asymmetric/asymmetric.component';


const routes: Routes = [
  { path: '', redirectTo: '/encryption', pathMatch: 'full' },
  { path: 'encryption', component: EncryptionComponent },
  { path: 'secret-sharing', component: SecretSharingComponent },
  { path: 'password', component: PasswordComponent },
  { path: 'utilities', component: UtilitiesComponent},
  { path: 'asymmetric', component: AsymmetricComponent}
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
