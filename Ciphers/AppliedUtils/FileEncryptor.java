package Ciphers.AppliedUtils;

import Ciphers.Basic.Cipher;
import Ciphers.Basic.HashFunction;
import Ciphers.Utils.FileUtil;

public class FileEncryptor {
    public static byte[] encrypt(java.io.File file, Cipher cipher){
        byte[] fileBytes = FileUtil.Read.read(file);
        fileBytes = cipher.encrypt(fileBytes);
        return fileBytes;
    }

    public static byte[] decrypt(java.io.File file, Cipher cipher){
        byte[] fileBytes = FileUtil.Read.read(file);
        fileBytes = cipher.decrypt(fileBytes);
        return fileBytes;
    }


    public static byte[] encrypt(java.io.File file, CipherCascade cipherCascade){
        byte[] fileBytes = FileUtil.Read.read(file);
        fileBytes = cipherCascade.encryptByCascade(fileBytes);
        return fileBytes;
    }

    public static byte[] decrypt(java.io.File file, CipherCascade cipherCascade){
        byte[] fileBytes = FileUtil.Read.read(file);
        fileBytes = cipherCascade.decryptByCascade(fileBytes);
        return fileBytes;
    }


    public static void encryptInFile(java.io.File file,Cipher cipher){
        byte[] fileBytesEncrypted = encrypt(file,cipher);
        FileUtil.Write.write(fileBytesEncrypted,file);

    }
    public static void decryptInFile(java.io.File file, Cipher cipher){
        byte[] fileBytesDecrypted = decrypt(file,cipher);
        FileUtil.Write.write(fileBytesDecrypted,file);
    }


    public static void encryptInFile(java.io.File file, CipherCascade cipherCascade){
        byte[] fileBytesEncrypted = encrypt(file,cipherCascade);
        FileUtil.Write.write(fileBytesEncrypted,file);

    }

    public static void decryptInFile(java.io.File file, CipherCascade cipherCascade){
        byte[] fileBytesDecrypted = decrypt(file,cipherCascade);
        FileUtil.Write.write(fileBytesDecrypted,file);
    }



    public static byte[] hash_summ(java.io.File file, HashFunction hashFunction){return hashFunction.process(FileUtil.Read.read(file));}
}
