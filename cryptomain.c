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

void write_encrypted_data_to_file(const char *filename, unsigned char *iv, unsigned char *ciphertext, int ciphertext_len) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Erreur lors de l'ouverture du fichier\n");
        return;
    }

    // Enregistrer l'IV
    if (fwrite(iv, 1, SHA_DIGEST_LENGTH, file) != SHA_DIGEST_LENGTH) {
        printf("Erreur lors de l'écriture de l'IV dans le fichier\n");
        fclose(file);
        return;
    }

    // Enregistrer la longueur du message chiffré
    if (fwrite(&ciphertext_len, sizeof(int), 1, file) != 1) {
        printf("Erreur lors de l'écriture de la longueur du message chiffré\n");
        fclose(file);
        return;
    }

    // Enregistrer ensuite le message chiffré
    if (fwrite(ciphertext, 1, ciphertext_len, file) != ciphertext_len) {
        printf("Erreur lors de l'écriture du message chiffré dans le fichier\n");
        fclose(file);
        return;
    }

    printf("Données chiffrées et IV enregistrées dans '%s'\n", filename);
    fclose(file);
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Erreur lors de l'initialisation du contexte AES pour le déchiffrement\n");
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        printf("Erreur lors de l'initialisation du déchiffrement AES\n");
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        printf("Erreur lors du déchiffrement AES\n");
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        printf("Erreur lors de la finalisation du déchiffrement AES\n");
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int read_encrypted_data_from_file(const char *filename, unsigned char *iv, unsigned char *ciphertext, int *ciphertext_len) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Erreur lors de l'ouverture du fichier pour la lecture\n");
        return 0;
    }

    // Lire l'IV d'abord
    if (fread(iv, 1, SHA_DIGEST_LENGTH, file) != SHA_DIGEST_LENGTH) {
        printf("Erreur lors de la lecture de l'IV\n");
        fclose(file);
        return 0;
    }

    // Lire la longueur du message chiffré
    if (fread(ciphertext_len, sizeof(int), 1, file) != 1) {
        printf("Erreur lors de la lecture de la longueur du message chiffré\n");
        fclose(file);
        return 0;
    }

    // Lire le message chiffré ensuite
    if (fread(ciphertext, 1, *ciphertext_len, file) != *ciphertext_len) {
        printf("Erreur lors de la lecture du message chiffré\n");
        fclose(file);
        return 0;
    }

    fclose(file);
    return 1;  // Succès
}

int main() {
    char input;
    printf("voulez vous chiffrer ou déchiffrer? c pour chiffrer, d pour déchiffrer\n");
    scanf(" %c", &input);
    switch(input)
    {
        case 'c':
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
             // Enregistrer l'IV et le message chiffré dans un fichier
            FILE *file = fopen("./cypted/encrypted_data.bin", "wb");
            if (!file) {
                printf("Erreur lors de l'ouverture du fichier\n");
                return 1;
            }

            // Enregistrer d'abord l'IV
            if (fwrite(iv, 1, SHA_DIGEST_LENGTH, file) != SHA_DIGEST_LENGTH) {
                printf("Erreur lors de l'écriture de l'IV dans le fichier\n");
                fclose(file);
                return 1;
            }

    // Enregistrer ensuite le message chiffré
            if (fwrite(ciphertext, 1, ciphertext_len, file) != ciphertext_len) {
                printf("Erreur lors de l'écriture du message chiffré dans le fichier\n");
                fclose(file);
                return 1;
            }

   
    }             
    return 0;
}
