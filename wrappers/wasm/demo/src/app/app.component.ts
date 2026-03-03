import { Component } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';
import { FaIconComponent } from '@fortawesome/angular-fontawesome';
import { faLock } from '@fortawesome/free-solid-svg-icons';
import * as functions from './shared/shared.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, FaIconComponent],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'devolutions-crypto-wasm-demo';
  faLock = faLock;

  w3Open() {
    functions.w3_open();
  }

  w3Close() {
    functions.w3_close();
  }
}
