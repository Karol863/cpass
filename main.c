#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

static void handleErrors(void);
static int encrypt(unsigned char *password, int password_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *password);

int main(void) {
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char salt[8];
    unsigned char password[34];
    unsigned char decryptedtext[34];
    unsigned char filename[38];
    unsigned char ciphertext[49];
    char choice[2];
    int decryptedtext_len, ciphertext_len;
    size_t written_bytes, read_bytes;

    if (!(RAND_bytes(iv, sizeof(iv)))) {
        handleErrors();
    }
    if (!(RAND_bytes(salt, sizeof(salt)))) {
        handleErrors();
    }

    printf("Enter filename (maximum 32 characters!)\n");
    if (fgets((char *)filename, sizeof(filename), stdin) == NULL) {
        puts("Filed to read filename!");
        return -1;
    }
    filename[strcspn((char *)filename, "\n")] = '\0';
    size_t l_filename = strlen((char *)filename);

    printf("Enter password (maximum 32 characters!)\n");
    if (fgets((char *)password, sizeof(password), stdin) == NULL) {
        puts("Failed to read password!");
        return -1;
    }
    password[strcspn((char *)password, "\n")] = '\0';
    size_t l_password = strlen((char *)password);

    printf("Encrypt(e) or Decrypt(d)?\n");
    if (fgets(choice, sizeof(choice), stdin) == NULL) {
        puts("Failed to read choice!");
        return -1;
    }
    choice[strcspn(choice, "\n")] = '\0';

    if (!(PKCS5_PBKDF2_HMAC((char *)password, l_password, salt, sizeof(salt), 1000, EVP_sha256(), sizeof(key), key))) {
        handleErrors();
    }

    if (choice[0] == 'e') {
        ciphertext_len = encrypt(password, l_password, key, iv, ciphertext);

        FILE *in = fopen(strncat((char *)filename, ".aes", sizeof(filename) - l_filename), "w");
        if (in == NULL) {
            puts("File error!");
            return -1;
        }
        written_bytes = fwrite(salt, sizeof(char), sizeof(salt), in);
        if (written_bytes != sizeof(salt)) {
            puts("failed to write salt into a file!");
            fclose(in);
            return -1;
        }
        written_bytes = fwrite(iv, sizeof(char), sizeof(iv), in);
        if (written_bytes != sizeof(iv)) {
            puts("Failed to write iv into a file!");
            fclose(in);
            return -1;
        }
        written_bytes = fwrite(ciphertext, sizeof(char), ciphertext_len, in);
        if ((int )written_bytes != ciphertext_len) {
            puts("Failed to write ciphertext into a file!");
            fclose(in);
            return -1;
        }
        fclose(in);
    } else if (choice[0] == 'd') {
        FILE *in = fopen(strncat((char *)filename, ".aes", sizeof(filename) - l_filename), "r");
        if (in == NULL) {
            puts("File error!");
            return -1;
        }
        read_bytes = fread(salt, sizeof(char), sizeof(salt), in);
        if (read_bytes != sizeof(salt)) {
            puts("Failed to read salt!");
            fclose(in);
            return -1;
        }
        read_bytes = fread(iv, sizeof(char), sizeof(iv), in);
        if (read_bytes != sizeof(iv)) {
            puts("Failed to read iv!");
            fclose(in);
            return -1;
        }
        ciphertext_len = fread(ciphertext, sizeof(char), sizeof(ciphertext), in);
        if (ciphertext_len <= 0) {
            puts("Failed to read ciphertext!");
            fclose(in);
            return -1;
        }
        fclose(in);

        if (!(PKCS5_PBKDF2_HMAC((char *)password, l_password, salt, sizeof(salt), 1000, EVP_sha256(), sizeof(key), key))) {
            handleErrors();
        }

        decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
        decryptedtext[decryptedtext_len] = '\0';

        puts("Password:");
        printf("%s\n", decryptedtext);
    }
    return 0;
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *password, int password_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int ciphertext_len, len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, password, password_len)) {
        handleErrors();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        handleErrors();
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *password) {
    EVP_CIPHER_CTX *ctx;
    int password_len, len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }
    if (1 != EVP_DecryptUpdate(ctx, password, &len, ciphertext, ciphertext_len)) {
        handleErrors();
    }
    password_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, password + len, &len)) {
        handleErrors();
    }
    password_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return password_len;
}
