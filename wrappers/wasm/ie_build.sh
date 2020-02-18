wasm2js devolutions_crypto_bg.wasm -o devolutions_crypto_bg.js
sed -i 's/export var /export var \_\_/' devolutions_crypto_bg.js
sed -i '/^import {/ d' devolutions_crypto_bg.js
sed -i '/^import \* as wasm/ d' devolutions_crypto.js
sed -i 's/wasm\./__/' devolutions_crypto.js
cat devolutions_crypto_bg.js >> devolutions_crypto.js