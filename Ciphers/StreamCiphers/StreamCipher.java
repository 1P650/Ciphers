package Ciphers.StreamCiphers;

import Ciphers.Basic.Cipher;

public abstract class StreamCipher extends Cipher {
    int KeySize = 0;
    int[] PossibleKeySizes;
    int IV_Size = 0;
    StreamCipherAlgorithm algorithm;

    protected StreamCipher(){

    }

    @Override
    public byte[] encrypt(byte[] input) {
        if(input == null || input.length == 0) throw new StreamCipherExeption(StreamCipherExeption.DATA_NULL);
        return algorithm.crypt(input);
    }

    @Override
    public byte[] decrypt(byte[] input) {
        if(input == null || input.length == 0) throw new StreamCipherExeption(StreamCipherExeption.DATA_NULL);
        return algorithm.crypt(input);
    }

    public int getIV_Size() {
        return this.IV_Size;
    }
    public int getKeySize() {
        return this.KeySize;
    }
    public int[] getPossibleKeySize() {
        return this.PossibleKeySizes;
    }


    public void reset(){
        this.algorithm = null;
    }
    public static StreamCipher getInstance(StreamCipher streamCipher) {
        return streamCipher;
    }


    public static StreamCipher getInstance(StreamCipher streamCipher, byte[] key) {
        streamCipher.setKey(key);
        return streamCipher;
    }

    public static StreamCipher getInstance(StreamCipher streamCipher,  byte[] key, byte[] iv) {
        streamCipher.setIV(iv);
        streamCipher.setKey(key);
        return streamCipher;
    }

    public abstract void setKey(byte[] key);

    public void setIV(byte[] IV) {
        if (IV == null || IV.length != getIV_Size()) throw new StreamCipherExeption(StreamCipherExeption.IV_LEN, getIV_Size() * 8, getIV_Size());
        algorithm.IV = IV;
    }

    protected final class StreamCipherExeption extends IllegalArgumentException {
        final static String KEY_LEN = "Key length must be %d bit (%d bytes)!";
        final static String DATA_NULL = "Data length must be >0!";
        final static String IV_NULL = "Initialization Vector is not set!";
        final static String IV_LEN = "IV length must be %d bit (%d bytes)!";

        StreamCipherExeption() {
            super();
        }
        StreamCipherExeption(String message) {
            super(message);
        }
        StreamCipherExeption(String message, Object... args) {
            super(String.format(message, args));
        }
        StreamCipherExeption(String message, String name) {
            super(String.format(message, name));
        }
    }



    protected abstract class StreamCipherAlgorithm{
        byte[] IV = null;
        StreamCipherAlgorithm(){
        }

        StreamCipherAlgorithm(byte[] key){

        }

        abstract byte[] crypt(byte[] input);


    }
}
