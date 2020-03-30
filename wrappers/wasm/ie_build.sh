# Convert to javascript
wasm2js devolutions_crypto_bg.wasm -o devolutions_crypto_bg.js

# Fix files
sed -i "s/import { getTempRet0 } from 'env'/var tempRet0\nfunction getTempRet0() {return tempRet0}\nfunction setTempRet0(data) {tempRet0 = data}/g" devolutions_crypto_bg.js
sed -i 's/export var /export var \_\_/g' devolutions_crypto_bg.js
sed -i '/^import {/ d' devolutions_crypto_bg.js
sed -i '/^import \* as wasm/ d' devolutions_crypto.js
sed -i 's/wasm\./\_\_/g' devolutions_crypto.js

# Combine the two files
cat devolutions_crypto_bg.js >> devolutions_crypto.js

# Rename package
mv devolutions_crypto.js devolutions_crypto_ie.js
mv devolutions_crypto.d.ts devolutions_crypto_ie.d.ts
sed -i '/devolutions_crypto_bg.wasm/ d' package.json
sed -i 's/devolutions-crypto/devolutions-crypto-ie/g' package.json
sed -i 's/devolutions_crypto/devolutions_crypto_ie/g' package.json

# Cleanup
rm devolutions_crypto_bg.js devolutions_crypto_bg.d.ts devolutions_crypto_bg.wasm
