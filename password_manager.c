#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct PasswordData {
    char service[30];
    char user[30];
    char password[30];
};
// XOR encryption/decryption
void xor_encrypt_decrypt(char *input, const char *key) {
    int len = strlen(input);
    int keyLen = strlen(key);
    int keyIndex = 0;

    // XOR each character in the input string with the corresponding character in the key
    for (int i = 0; i < len; ++i) {
        input[i] ^= key[keyIndex];
        keyIndex = (keyIndex + 1) % keyLen;
    }
}

// Encrypt the password using XOR and the master key
void encrypt_password(const char *password, char *encryptedPassword, const char *masterKey) {
    const char xorKey[] = "project_on_password_maagement"; 

    // Copy the original password to the encrypted password
    strcpy(encryptedPassword, password);

    // Encrypt the password using XOR
    xor_encrypt_decrypt(encryptedPassword, xorKey);

    // Further encrypt with the master key
    xor_encrypt_decrypt(encryptedPassword, masterKey);
}

// Decrypt the password using XOR and the master key
void decrypt_password(const char *encryptedPassword, char *decryptedPassword, const char *masterKey) {
    const char xorKey[] = "project_on_password_maagement"; // Replace with your own XOR key

    // Copy the encrypted password to the decrypted password
    strcpy(decryptedPassword, encryptedPassword);

    // Decrypt with the master key
    xor_encrypt_decrypt(decryptedPassword, masterKey);

    // Decrypt the password using XOR
    xor_encrypt_decrypt(decryptedPassword, xorKey);
}

// Add a new password to the file
void add_password(FILE *file, const char *masterKey) {
    struct PasswordData entry;

    printf("Enter service name: ");
    scanf("%s", entry.service);

    printf("Enter username: ");
    scanf("%s", entry.user);

    printf("Enter password: ");
    scanf("%s", entry.password);

    char encryptedPassword[30];
    encrypt_password(entry.password, encryptedPassword, masterKey);

    fprintf(file, "%s %s %s\n", entry.service, entry.user, encryptedPassword);
}

// Show all passwords in the file
void showPasswords(FILE *file, const char *masterKey) {
    struct PasswordData entry;

    while (1) {
        char userProvidedKey[50];
        printf("Enter your master key to show passwords (or type 'exit' to go back): ");
        scanf("%s", userProvidedKey);

        if (strcmp(userProvidedKey, masterKey) == 0) {
            printf("Authenticated successfully.\n");
            break; // Correct master key, exit the loop
        } else if (strcmp(userProvidedKey, "exit") == 0) {
            return; // User wants to go back
        } else {
            printf("Incorrect master key. Try again or type 'exit' to go back.\n");
        }
    }

    rewind(file); // Move the file pointer to the beginning of the file

    while (fscanf(file, "%s %s %s", entry.service, entry.user, entry.password) == 3) {
        char decryptedPassword[30];
        decrypt_password(entry.password, decryptedPassword, masterKey);

        printf("Service: %s\n", entry.service);
        printf("Username: %s\n", entry.user);
        printf("Password: %s\n", decryptedPassword);
    }
}

// Delete a password from the file
void deletePassword(FILE *file) {
    char serviceName[30];
    char username[30];

    printf("Enter service name for the password to delete: ");
    scanf("%s", serviceName);

    printf("Enter username for the password to delete: ");
    scanf("%s", username);

    FILE *tempFile = fopen("temp.txt", "w");
    if (tempFile == NULL) {
        printf("Error opening temporary file.\n");
        exit(EXIT_FAILURE);
    }

    struct PasswordData entry;

    // Copy all passwords except the one to be deleted to the temporary file
    while (fscanf(file, "%s %s %s", entry.service, entry.user, entry.password) == 3) {
        if (strcmp(entry.service, serviceName) != 0 || strcmp(entry.user, username) != 0) {
            fprintf(tempFile, "%s %s %s\n", entry.service, entry.user, entry.password);
        }
    }

    fclose(file);
    fclose(tempFile);

    remove("passwords.txt");
    rename("temp.txt", "passwords.txt");

    printf("Password deleted successfully.\n");
}

// Search for a password in the file 
void searchPassword(FILE *file) {
    char serviceName[30];
    char username[30];

    printf("Enter service name to search: ");
    scanf("%s", serviceName);

    printf("Enter username to search: ");
    scanf("%s", username);

    struct PasswordData entry;
    int found = 0;

    while (fscanf(file, "%s %s %s", entry.service, entry.user, entry.password) == 3) {
        if (strcmp(entry.service, serviceName) == 0 && strcmp(entry.user, username) == 0) {
            char decryptedPassword[30];
            decrypt_password(entry.password, decryptedPassword, "");

            printf("Service: %s\n", entry.service);
            printf("Username: %s\n", entry.user);
            printf("Password: %s\n", decryptedPassword);

            found = 1;
            break; // Stop searching after finding the first match
        }
    }

    if (!found) {
        printf("Password not found.\n");
    }
}

int main() {
    char masterKey[30];
    FILE *fptr = fopen("master_key.txt", "r");
    if (fptr == NULL) {
        printf("Welcome to Secure Password Manager\n");
        printf("Set your master key: ");
        scanf("%s", masterKey);
        xor_encrypt_decrypt(masterKey, "project_on_password_maagement");
        fptr = fopen("master_key.txt", "w");
        fprintf(fptr, "%s", masterKey);
        xor_encrypt_decrypt(masterKey, "project_on_password_maagement");
    }
    else {
        fscanf(fptr, "%s", masterKey);
        xor_encrypt_decrypt(masterKey, "project_on_password_maagement");
    }
    fclose(fptr);

    //char masterKey[50];
   // printf("Set your master key: ");
   // scanf("%s", masterKey);
    FILE *file = fopen("passwords.txt", "a+");
    int choice;
    do {
        printf("\n1. Add password\n");
        printf("2. Show passwords\n");
        printf("3. Delete password\n");
        printf("4. Search password\n");
        printf("5. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                add_password(file, masterKey);
                break;
            case 2:
                showPasswords(file, masterKey);
                break;
            case 3:
                deletePassword(file);
                break;
            case 4:
                searchPassword(file);
                break;
            case 5:
                printf("Exiting the program. Goodbye!\n");
                break;
                exit(1);
            default:
                printf("Invalid choice. Please enter a valid option.\n");
        }

    } while (choice != 5);

    fclose(file);

    return 0;
}
