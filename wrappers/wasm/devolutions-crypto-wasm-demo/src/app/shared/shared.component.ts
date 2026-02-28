export function w3_open() {
  (document.getElementById('mySidebar') as HTMLElement).style.display = 'flex';
  (document.getElementById('myOverlay') as HTMLElement).style.display = 'block';
}

export function w3_close() {
  (document.getElementById('mySidebar') as HTMLElement).style.display = 'none';
  (document.getElementById('myOverlay') as HTMLElement).style.display = 'none';
}
