# devolutions-crypto

Cryptographic library used in Devolutions products. It is made to be fast, easy to use and misuse-resistant.

# Usage
You can refer to the [Angular example](demo/) or the [unit tests](tests/) to see how to use the library.

# Known Issue

On Firefox, exception shows up as `Error` in the console if not caught, but the value of `error.name` is the right one, so you can still try/catch depending on the error name.