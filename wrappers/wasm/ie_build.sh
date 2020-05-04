cd dist/bundler

# Convert to javascript
wasm2js devolutions_crypto_bg.wasm -o devolutions_crypto_bg.js

# Fix files
sed -i '' "s/import { getTempRet0 } from 'env'/var tempRet0;function getTempRet0() {return tempRet0};function setTempRet0(data) {tempRet0 = data}/g" devolutions_crypto_bg.js
sed -i '' 's/export var /export var \_\_/g' devolutions_crypto_bg.js
sed -i '' '/^import {/ d' devolutions_crypto_bg.js
sed -i '' '/^import \* as wasm/ d' devolutions_crypto.js
sed -i '' 's/wasm\./\_\_/g' devolutions_crypto.js

# Combine the two files
cat devolutions_crypto_bg.js >> devolutions_crypto.js

# Rename package
mv devolutions_crypto.js devolutions_crypto_ie_init.js
mv devolutions_crypto.d.ts devolutions_crypto_ie.d.ts
sed -i '' '/devolutions_crypto_bg.wasm/ d' package.json
sed -i '' 's/devolutions-crypto/devolutions-crypto-ie/g' package.json
sed -i '' 's/devolutions_crypto/devolutions_crypto_ie/g' package.json

# Prepare browserlist
# Babel for browser compat
npm install --save-dev @babel/core @babel/preset-env @babel/cli
echo 'running babel-cli'
npx babel devolutions_crypto_ie_init.js --out-file devolutions_crypto_ie.js --presets=@babel/preset-env

# Cleanup
sed -i '' '/devolutions_crypto_ie_bg.js/ d' package.json
rm devolutions_crypto_bg.js devolutions_crypto_bg.d.ts devolutions_crypto_bg.wasm devolutions_crypto_ie_init.js