--------------------------------------------- Asymmetrical Encryption---------------------------------------------   

    Generate a key pair :
        1.  EC_KEY and EC_GROUP object
        2.  EC_KEY_set_group to set EC_GROUP of EC_KEY
        3.  EC_KEY_generate_key, create a pair of public key and private key, 
            the pair shall be stored in EC_KEY

    Save public key :
        1. EVP_PKEY *keypair
        2. EVP_PKEY_assign_EC_KEY with keypair and EC_KEY
        3. Open a file , using file stream in function PEM_write_EC_PUBKEY
        4. Close file descriptor

    Save private key:
        The same with public key except the function would be PEM_write_ECPrivateKey

    Sign/Verify Challange:
        Intro : 
            The secret shall be send between 2 machine, this secret first would be 
            signed by client by its own private key and sent to server.
            When server receives this signed secret, it verigy the secret
            using the public key of client. If not right, then reject the connection

        Sign challenge
            1. EVP_MD *digest
            2. size_t sig_size ECDSA_size
            3. ECDSA_sign

        Verify challenge
            1. EVP_MD *digest
            2. ECDSA_size
            3. ECDSA_verify

    Read key from file:
        PEM_read_PUBKEY
        PEM_read_PrivateKey


---------------------------------------------Symmetrical encryption---------------------------------------------

Both client and server would be using the same shared secret key to encrypt and decrypt the message. 
The client will be the one to create a random number of bytes that is called a shared secret.
The data send from client to server and vice versa would be encrypt/decrypt with the help of function 
in openSSL 

1. EVP_CIPHER_CTX *ctx
2. EVP_DecryptInit_ex/EVP_EncryptInit_ex function with ctx to set the type of algorithm would be used
3. EVP_CipherUpdate to execute the encryption/decryption 
