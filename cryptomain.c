#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>


int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Erreur lors de l'initialisation du contexte AES\n");
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        printf("Erreur lors de l'initialisation du chiffrement AES\n");
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        printf("Erreur lors du chiffrement AES\n");
        return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        printf("Erreur lors de la finalisation du chiffrement AES\n");
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


void sha1_hash(const unsigned char *input, size_t input_len, unsigned char *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        printf("Erreur lors de l'initialisation du contexte SHA1\n");
        return;
    }

    const EVP_MD *md = EVP_sha1();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, input, input_len);
    EVP_DigestFinal_ex(ctx, output, NULL);

    EVP_MD_CTX_free(ctx);
}

void print_hash(const char *label, const unsigned char *hash, size_t hash_len) {
    printf("%s : ", label);
    for (size_t i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    char password[16];
    char message[256];
    unsigned char buffer[16];
    RAND_bytes(buffer, 16);
    printf("Entrez un mot de passe : ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';  

    printf("Entrez un message à chiffrer : ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = '\0';  

    unsigned char iv[SHA_DIGEST_LENGTH];
    unsigned char key[16];
    unsigned char ciphertext[256];

    
    sha1_hash((unsigned char *)password, strlen(password), key);
    print_hash("key (SHA1 du mot de passe)", key, 16);

    
    sha1_hash((unsigned char *)buffer, 16, iv);
    print_hash("IV", iv, SHA_DIGEST_LENGTH);

    
    int ciphertext_len = aes_encrypt((unsigned char *)message, strlen(message), key, iv, ciphertext);

    if (ciphertext_len < 0) {
        printf("Erreur lors du chiffrement\n");
        return 1;
    }

    printf("Message chiffré : ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
