export function w3_open() {
  document.getElementById('mySidebar').style.display = 'block';
  document.getElementById('myOverlay').style.display = 'block';
}

export function w3_close() {
  document.getElementById('mySidebar').style.display = 'none';
  document.getElementById('myOverlay').style.display = 'none';
}
