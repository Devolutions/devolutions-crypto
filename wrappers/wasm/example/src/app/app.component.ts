import { Component } from '@angular/core';
import { faLock } from '@fortawesome/free-solid-svg-icons';
import * as functions from './shared/shared.component';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.styl']
})
export class AppComponent {
  title = 'devolutions-crypto-example';
  faLock = faLock;

  w3Open() {
    functions.w3_open();
  }

  w3Close() {
    functions.w3_close();
  }
}
