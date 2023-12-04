# Password Manager in C

This is a simple password manager written in C. It uses XOR encryption to secure passwords.

## Files

- `password_manager.c`: This is the main file of the project.
- `passwords.txt`: This file contains the encrypted passwords.
- `master_key.txt`: This file contains the master key used for encryption.

## Structures

- `PasswordData`: This structure holds the service name, username, and password.

## Functions

- `xor_encrypt_decrypt(char *input, const char *key)`: This function performs XOR encryption/decryption on the input string using the provided key.

- `encrypt_password(const char *password, char *encryptedPassword, const char *masterKey)`: This function encrypts the password using XOR and the master key.

- `decrypt_password(const char *encryptedPassword, char *password, const char *masterKey)`: This function decrypts the password using XOR and the master key.

- `void add_password(FILE *file, const char *masterKey)`: This function gets the password data for the given service name.

- `void showPasswords(FILE *file, const char *masterKey)`: This function shows all the passwords in the file.

- `void deletePassword(FILE *file)`: This function deletes a password from the file.

- `void searchPassword(FILE *file)`: This function searches for a password in the file.

## How to Run

1. Compile the C file using a C compiler (like gcc).
2. Run the compiled file.

## Note

This project is for educational purposes only. XOR encryption is not secure for real-world password management.
