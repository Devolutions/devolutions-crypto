import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { AppComponent } from './app.component';
import { EncryptionComponent } from './encryption/encryption.component';
import { SecretSharingComponent } from './secret-sharing/secret-sharing.component';
import { PasswordComponent } from './password/password.component';
import { AppRoutingModule } from './app-routing.module';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { UtilitiesComponent } from './utilities/utilities.component';
import { AsymmetricComponent } from './asymmetric/asymmetric.component';

@NgModule({
  declarations: [
    AppComponent,
    EncryptionComponent,
    SecretSharingComponent,
    SecretSharingComponent,
    PasswordComponent,
    UtilitiesComponent,
    AsymmetricComponent
  ],
  imports: [
    BrowserModule,
    FormsModule,
    ReactiveFormsModule,
    AppRoutingModule,
    FontAwesomeModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
