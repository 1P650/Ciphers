# Ciphers

Just implementation of different ciphers/hash functions/others.
#### WARNING: Some of them might be not correctly implemented.

## Contains 
### Ciphers
#### Block Ciphers
* Aardvark
* GOST28147-89 (ГОСТ28147-89) (ECB mode,CFB mode, CTR mode, MAC (Imitovstavka)) 
* TEA (Tiny Encryption Algorithm) (ECB mode, CBC mode, OFB mode, CFB mode, CTR mode)
* IDEA (International Data Encryption Algorithm) (ECB mode, CBC mode, OFB mode, CFB mode, CTR mode)
* CAST-128 (CAST5) (ECB mode, CBC mode, OFB mode, CFB mode, CTR mode)
* CAST-256 (CAST6) (ECB mode, CBC mode, OFB mode, CFB mode, CTR mode)
* Cobra (Cobra128) (ECB mode, CBC mode, OFB mode, CFB mode, CTR mode)

##### Usage 
```java
BlockCipher cipher = BlockCipher.getInstance(BlockCiphersList.name, BlockCipher.mode);
cipher.setKey(KEY);
cipher.setIV(IV);
byte[] enc = cipher.encrypt(plain);
byte[] dec = cipher.decrypt(enc);
```

#### Stream Ciphers
* Rabbit
* HC-256
* Trivium

##### Usage 
```java
StreamCipher cipher = StreamCipher.getInstance(StreamCiphersList.name);
cipher.setKey(KEY);
cipher.setIV(IV);
byte[] enc = cipher.encrypt(plain);
byte[] dec = cipher.decrypt(enc
```

#### Primitive Ciphers
* ROTn or Caesar
* One-time XOR pad or Vernam
* Vigenere

##### Usage
```java
Cipher cipher = new Caesar();
cipher.setKey(10);
byte[] enc = cipher.encrypt(plain);
byte[] dec = cipher.decrypt(enc
```

***
### Hash Functions
* SHA1
* SHA2: SHA224, SHA256, SHA384, SHA512, SHA512/256, SHA512/224

##### Usage
```java
HashFunction function = new HashFunctionName();
byte[] hash = function.process(plain);
```

***
### Pseudorandom number generators
* Simple linear congruential PRNG
* ISAAC CSPRNG (not correctly implemented but still)
***

### Applied utils
* Cascade encryption (CipherCascade)
* File Encryption (FileEncryptor)
***

### Utils
* BitUtil (bit rotation, type conversion, hex&binary print,more)
* AlgorithmUtil (index of element, reverse array, reverse matrix)
* MathUtil (modulo operations, more will be soon)
* FileUtil (java.io.File; Read,Write,Hash)




