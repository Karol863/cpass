#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "memory.h"

static void handleErrors(void);
static int encrypt(unsigned char *password, int password_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *password);

int main(void) {
	unsigned char key[32] = {0};
	unsigned char iv[16] = {0};
	unsigned char salt[8] = {0};
	unsigned char ciphertext[49] = {0};
	unsigned char decryptedtext[33] = {0};

	char password[34] = {0};
	char filename[38] = {0};
	char option[2] = {0};
	int decryptedtext_len = 0;
	int ciphertext_len = 0;

	if (unlikely(RAND_bytes(iv, sizeof(iv)) != 1)) {
		handleErrors();
	}
	if (unlikely(RAND_bytes(salt, sizeof(salt)) != 1)) {
		handleErrors();
	}

	puts("Enter password (Maximum 32 characters!)");
	if (unlikely(fgets(password, sizeof(password), stdin) == NULL)) {
		fputs("Failed to read the password!\n", stderr);
		return -1;
	}

	puts("Enter filename (Maximum 32 characters!)");
	if (unlikely(fgets(filename, sizeof(filename), stdin) == NULL)) {
		fputs("Failed to read the filename!\n", stderr);
		return -1;
	}

	puts("Enter option (Either e or d)");
	if (unlikely(fgets(option, sizeof(option), stdin) == NULL)) {
		fputs("Failed to read the option!\n", stderr);
		return -1;
	}

	password[strcspn(password, "\n")] = '\0';
	filename[strcspn(filename, "\n")] = '\0';
	option[strcspn(option, "\n")] = '\0';

	u8 password_len = strlen(password);

	if (unlikely(PKCS5_PBKDF2_HMAC(password, password_len, salt, sizeof(salt), 10000, EVP_sha256(), sizeof(key), key) != 1)) {
		handleErrors();
	}

	if (option[0] == 'e') {
		ciphertext_len = encrypt((unsigned char *)password, password_len, key, iv, ciphertext);

		FILE *f = fopen(strncat(filename, ".aes", 5), "w");
		if (f == NULL) {
			fputs("File not found!\n", stderr);
			return -1;
		}

		fwrite(iv, 1, sizeof(iv), f);
		fwrite(key, 1, sizeof(key), f);
		fwrite(ciphertext, 1, ciphertext_len, f);
		if (unlikely(ferror(f))) {
			fputs("Failed to write data into a file!\n", stderr);
			fclose(f);
			return -1;
		}

		fclose(f);
	} else if (option[0] == 'd') {
		FILE *f = fopen(strncat(filename, ".aes", 4), "r");
		if (f == NULL) {
			fputs("File not found!\n", stderr);
			return -1;
		}

		fread(iv, 1, sizeof(iv), f);
		fread(key, 1, sizeof(key), f);
		ciphertext_len = fread(ciphertext, 1, sizeof(ciphertext), f);
		if (unlikely(ferror(f))) {
			fputs("Failed to read from a file!\n", stderr);
			fclose(f);
			return -1;
		}

		fclose(f);

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
	int ciphertext_len = 0;
	int len = 0;

	if (unlikely((ctx = EVP_CIPHER_CTX_new()) == NULL)) {
		handleErrors();
	}
	if (unlikely(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)) {
		handleErrors();
	}
	if (unlikely(EVP_EncryptUpdate(ctx, ciphertext, &len, password, password_len) != 1)) {
		handleErrors();
	}
	ciphertext_len = len;

	if (unlikely(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)) {
		handleErrors();
	}
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *password) {
	EVP_CIPHER_CTX *ctx;
	int password_len = 0;
	int len = 0;

	if (unlikely((ctx = EVP_CIPHER_CTX_new()) == NULL)) {
		handleErrors();
	}
	if (unlikely(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)) {
		handleErrors();
	}
	if (unlikely(EVP_DecryptUpdate(ctx, password, &len, ciphertext, ciphertext_len) != 1)) {
		handleErrors();
	}
	password_len = len;

	if (unlikely(EVP_DecryptFinal_ex(ctx, password + len, &len) != 1)) {
		handleErrors();
	}
	password_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return password_len;
}
