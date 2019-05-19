package Ciphers.Basic;

public interface Cipher {

     void setKey(byte[] key);
     byte[] encrypt(byte[] plain);
     byte[] decrypt(byte[] ciph);
     void reset();


}
