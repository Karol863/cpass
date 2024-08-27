#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

static void handleErrors(void);
static int encrypt(unsigned char *password, int password_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *password);

int main(void) {
	unsigned char key[32];
	unsigned char iv[16];
	unsigned char salt[8];
	unsigned char ciphertext[49];
	unsigned char decryptedtext[34];

	unsigned char password[34];
	unsigned char filename[38];
	char choice[2];
	int decryptedtext_len, ciphertext_len;

	if (!(RAND_bytes(iv, sizeof(iv)))) {
		handleErrors();
	}
	if (!(RAND_bytes(salt, sizeof(salt)))) {
		handleErrors();
	}

	printf("Enter password (Maximum 32 characters!)\n");
	fgets((char *)password, sizeof(password), stdin);

	printf("Enter filename (Maximum 32 characters!)\n");
	fgets((char *)filename, sizeof(filename), stdin);

	printf("Enter choice (Either e or d)\n");
	fgets(choice, sizeof(choice), stdin);

	size_t password_len = strlen((char *)password);
	size_t filename_len = strlen((char *)filename);

	password[strcspn((char *)password, "\n")] = '\0';
	filename[strcspn((char *)filename, "\n")] = '\0';
	choice[strcspn(choice, "\n")] = '\0';

	if (!(PKCS5_PBKDF2_HMAC((char *)password, password_len, salt, sizeof(salt), 10000, EVP_sha256(), sizeof(key), key))) {
		handleErrors();
	}

	if (choice[0] == 'e') {
		ciphertext_len = encrypt(password, password_len, key, iv, ciphertext);

		FILE *fp = fopen(strncat((char *)filename, ".aes", sizeof(filename) - filename_len), "w");
		if (fp == NULL) {
			fputs("Failed to open file!\n", stderr);
			return -1;
		}

		fwrite(iv, sizeof(char), sizeof(iv), fp);
		fwrite(key, sizeof(char), sizeof(key), fp);
		fwrite(ciphertext, sizeof(char), ciphertext_len, fp);

		fclose(fp);
	} else if (choice[0] == 'd') {
		FILE *fp = fopen(strncat((char *)filename, ".aes", sizeof(filename) - filename_len), "r");
		if (fp == NULL) {
			fputs("Failed to open file!\n", stderr);
			return -1;
		}

		fread(iv, sizeof(char), sizeof(iv), fp);
		fread(key, sizeof(char), sizeof(key), fp);
		ciphertext_len = fread(ciphertext, sizeof(char), sizeof(ciphertext), fp);

		fclose(fp);

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

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *password) {
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
