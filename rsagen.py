import PRBG

if __name__ == '__main__':
    seed = "password"

    rsa_key = PRBG.generate_RSA_key_pai()
    PRBG.write_private_key_to_pem("private_key4.pem", rsa_key)
    PRBG.write_public_key_to_pem("public_key4.pem", rsa_key.public_key())