# A5/1 Stream Cipher Cryptanalysis (Known Plaintext Attack)

This project was developed for the **Applied Cryptography (ENCS4320)** course at **Birzeit University**.

## Project Description

This project performs a cryptanalytic attack on the GSM **A5/1 stream cipher**.

The goal is to recover the unknown initial state of **LFSR Y (22 bits)** using a **known plaintext attack**.

Given:

- Initial states of LFSR X and Z
- Known portion of the plaintext
- Full ciphertext

The program brute-forces all possible values of the unknown **LFSR Y** state.

## Attack Method

Steps used in the attack:

1. Convert known plaintext into binary bits
2. Read the ciphertext bits
3. Brute-force all 2²² possible states of LFSR Y
4. Generate keystream using the A5/1 algorithm
5. Compare the generated keystream with the XOR of ciphertext and known plaintext
6. Once the correct state is found:
   - Recover the full keystream
   - Decrypt the entire ciphertext

## Optimization

To speed up the brute-force process:

- Only the first **24 bits** of keystream are compared initially
- This reduces the runtime from about **30 minutes to ~3 minutes**
