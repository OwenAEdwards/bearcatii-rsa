"""
  Activity: Assignment 2
  File:     HW_2_CS7081_Group_19.py
  Date:     9 2 2024
  By:       Shraddha Kiran Burra, Owen Edwards, Lucas Jividen, Dale Luginbuhl
  Group:    19
"""

def gcd(a : int, b: int) -> int:
    """
    Calculate the greatest common divisor (GCD) of two numbers using Euclidean
    algorithm
    """
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a: int, m: int):
    """
    Compute the modular inverse of 'a' modulo 'm'
    """
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def encode_bearcatii(message: str) -> str:
    """
    Convert each character to its assigned integer value in BEARCATII encoding
    e.g. "abc" -> [1, 2, 3]
    """
    encoded_message = []
    for char in message:
        if char.isalpha() and char.islower():
            # Numeric position = lower-case char (97 to 122) - 97 + 1 = 1 to 26
            encoded_message.append(ord(char) - ord('a') + 1)
        else:
            # Use 0 for non-valid characters
            encoded_message.append(0)
    return encoded_message

def decode_bearcatii(encoded_message: str) -> str:
    """
    Convert integers back to characters using BEARCATII decoding
    e.g. [1, 2, 3] -> "abc"
    """
    decoded_message = []
    for value in encoded_message:
        # Valid lowercase values will be between 1 and 26, inclusive
        if 1 <= value <= 26:
            # Char position = BEARCATII (1 to 26) + 97 - 1 = 97 to 122
            decoded_message.append(chr(value + ord('a') - 1))
        else:
            # Use " " for non-valid characters; when value == 0
            decoded_message.append(" ")
        return ''.join(decoded_message)

def rsa_encrypt(message: str, e: int, n: int) -> str:
    """
    Encrypt the message using RSA
    """
    encoded_message = encode_bearcatii(message)
    ciphertext = []
    for value in encoded_message:
        # Modular exponentiation: (Numeric BEARCATII char position)^e mod n
        ciphertext.append(pow(value, e) % n)
    return ciphertext

def rsa_decrypt(ciphertext: str, d: int, n: int) -> str:
    """
    Decrypt the ciphertext to obtain the original message
    """
    plaintext = []
    for encrypted_value in ciphertext:
        # Modular exponentiation
        decrypted_value = pow(encrypted_value, d) % n

        # Valid lowercase values will be between 1 and 26, inclusive
        if 1 <= decrypted_value <= 26:
            # Char position = BEARCATII (1 to 26) + 97 - 1 = 97 to 122
            plaintext.append(chr(decrypted_value + ord('a') - 1))
        else:
            # Use " " for non-valid characters; when decrypted_value == 0
            plaintext.append(" ")

    return ''.join(plaintext)

def main():
    # Example: M = "test"
    p, q = 61, 53  # Choose prime numbers (replace with actual primes)
    n = p * q
    # The Euler Totient Function (ETF) is phi_n
    phi_n = (p - 1) * (q - 1)

    # Input public key
    e = int(input("Enter a positive integer for the public key (e): "))
    while gcd(e, phi_n) != 1:
        e = int(input("Invalid choice. Enter a different e: "))

    message = input("Enter the message (in lowercase letters): ")
    ciphertext = rsa_encrypt(message, e, n)

    # Compute private key
    d = mod_inverse(e, phi_n)
    
    plaintext = rsa_decrypt(ciphertext, d, n)

    print(f"p: {p}, q: {q}, n: {n}")
    print(f"Message (M): {message}")
    print(f"Ciphertext (C): {ciphertext}")
    print(f"Plaintext (P): {plaintext}")

if __name__ == "__main__":
    main()
