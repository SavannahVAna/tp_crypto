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

int main() {
    char input;
    int ciphertext_len;
    printf("Voulez-vous chiffrer ou déchiffrer ? (c pour chiffrer, d pour déchiffrer) : ");
    scanf(" %c", &input);
    getchar(); 

    switch (input) {
        case 'c': {
            char password[16];
            char message[256];
            unsigned char buffer[16];
            RAND_bytes(buffer, 16);
            //char message2[5] = "oooo";
            
            printf("Entrez un mot de passe : ");
            fgets(password, sizeof(password), stdin);
            password[strcspn(password, "\n")] = '\0';

            printf("Entrez un message à chiffrer : ");
            fgets(message, sizeof(message), stdin);
            message[strcspn(message, "\n")] = '\0';
            //strncpy(message2,message, 5);
            //printf("%s",message);
            unsigned char iv[16];
            unsigned char key[16];
            unsigned char ciphertext[256];

            
            sha1_hash((unsigned char *)password, strlen(password), key);
            print_hash("Clé (SHA1 du mot de passe)", key, 16);

            sha1_hash(buffer, 16, iv);
            print_hash("IV", iv, 16);

            // Chiffrement du message
            ciphertext_len = aes_encrypt((unsigned char *)message, strlen(message), key, iv, ciphertext);
            if (ciphertext_len < 0) {
                printf("Erreur lors du chiffrement\n");
                return 1;
            }

            printf("Message chiffré : ");
            for (int i = 0; i < ciphertext_len; i++) {
                printf("%02x", ciphertext[i]);
            }
            printf("\n");

            // Enregistrement dans les fichiers
            FILE *file = fopen("./encrypted_data.bin", "wb");
            if (!file) {
                printf("Erreur lors de l'ouverture du fichier\n");
                return 1;
            }

            FILE *fileiv = fopen("./encrypted_IV.bin", "wb");
            if (!fileiv) {
                printf("Erreur lors de l'ouverture du fichier pour IV\n");
                return 1;
            }

            // Enregistrer l'IV dans un fichier
            if (fwrite(iv, 1, 16, fileiv) != 16) {
                printf("Erreur lors de l'écriture de l'IV dans le fichier\n");
                fclose(file);
                fclose(fileiv);
                return 1;
            }
            fclose(fileiv);

            // Enregistrer le message chiffré dans un fichier
            if (fwrite(ciphertext, 1, (size_t)ciphertext_len, file) != (size_t)ciphertext_len) {
                printf("Erreur lors de l'écriture du message chiffré\n");
            }
            fclose(file);
            break;
        }
        case 'd': {
            char password[16];
            unsigned char iv[16];
            unsigned char key[16];
            unsigned char ciphertext[256];
            unsigned char decrypted_message[256];

            FILE *file = fopen("./encrypted_data.bin", "rb");
            if (!file) {
                printf("Erreur lors de l'ouverture du fichier de données chiffrées\n");
                return 1;
            }

            FILE *fileiv = fopen("./encrypted_IV.bin", "rb");
            if (!fileiv) {
                printf("Erreur lors de l'ouverture du fichier IV\n");
                fclose(file);
                return 1;
            }

            printf("Entrez un mot de passe : ");
            fgets(password, sizeof(password), stdin);
            password[strcspn(password, "\n")] = '\0';

            
            if (fread(iv, 1, 16, fileiv) != 16) {
                printf("Erreur lors de la lecture de l'IV depuis le fichier\n");
                fclose(file);
                fclose(fileiv);
                return 1;
            }
            fclose(fileiv);

        
            fseek(file, 0, SEEK_END);
            ciphertext_len = ftell(file);  // Obtenir la taille du texte chiffré
            fseek(file, 0, SEEK_SET);
            if (fread(ciphertext, 1, ciphertext_len, file) != (size_t)(ciphertext_len)) {
                printf("Erreur lors de la lecture du message chiffré\n");
            }
            fclose(file);

            // Génération de la clé
            sha1_hash((unsigned char *)password, strlen(password), key);
            print_hash("Clé (SHA1 du mot de passe)", key, 16);

            // Déchiffrement du message
            int decrypted_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, decrypted_message);
            if (decrypted_len < 0) {
                printf("Erreur lors du déchiffrement\n");
                return 1;
            }

            decrypted_message[decrypted_len] = '\0';
            printf("Message déchiffré : %s\n", decrypted_message);
            break;
        }
        default:
            printf("Option invalide\n");
    }

    return 0;
}
