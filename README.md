A simple password manager that uses the OpenSSL libraries for encryption and decryption. Made with the goal of learning C.

## Dependencies

* [OpenSSL](https://www.openssl.org/)

## Building
This example uses gcc, but this will work with clang as well.

```console
gcc -o password-manager main.c -Wall -Wextra -Wwrite-strings -Wno-unused-result -march=native -O2 -ftree-vectorize -fno-semantic-interposition -fno-plt -pipe -s -flto -D_FORTIFY_SOURCE=2 -lcrypto
```
