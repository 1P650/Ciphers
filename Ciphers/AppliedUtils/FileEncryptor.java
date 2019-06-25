package Ciphers.AppliedUtils;

public class FileEncryptor {
    public byte[] encrypt(java.io.File file, Cipher cipher){return null;}
    public byte[] decrypt(java.io.File file, Cipher cipher){return null;}
    public byte[] encrypt(java.io.File[] file, Cipher cipher){return null;}
    public byte[] decrypt(java.io.File[] file, Cipher cipher){return null;}
    public byte[] encrypt(java.io.File file, CipherCascade cipherCascade){return null;}
    public byte[] decrypt(java.io.File file, CipherCascade cipherCascade){return null;}


    public java.io.File encryptInFile(java.io.File file,Cipher cipher){return null;}
    public java.io.File decryptInFile(java.io.File file, Cipher cipher){return null;}
    public java.io.File encryptInFile(java.io.File[] file, Cipher cipher){return null;}
    public java.io.File decryptInFile(java.io.File[] file, Cipher cipher){return null;}
    public java.io.File encryptInFile(java.io.File file, CipherCascade cipherCascade){return null;}
    public java.io.File decryptInFile(java.io.File file, CipherCascade cipherCascade){return null;}

    public java.io.File encryptInFile(java.io.FileInputStream fis,Cipher cipher){return null;}
    public java.io.File decryptInFile(java.io.FileInputStream fis, Cipher cipher){return null;}
    public java.io.File encryptInFile(java.io.FileInputStream[] fis, Cipher cipher){return null;}
    public java.io.File decryptInFile(java.io.FileInputStream[] fis, Cipher cipher){return null;}
    public java.io.File encryptInFile(java.io.FileInputStream fis, CipherCascade cipherCascade){return null;}
    public java.io.File decryptInFile(java.io.FileInputStream fis, CipherCascade cipherCascade){return null;}

    public byte[] Hash(java.io.File file, HashFunction hashFunction){return null;}
    public byte[] Hash(java.io.FileInputStream fis, HashFunction hashFunction){return null;}
}
