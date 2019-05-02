package BlockCiphers;

import Basic.Cipher;
import Basic.algorithmUtil;
import Basic.bitUtil;


public class GOST_89 implements Cipher {
    public final static byte ECB = 0;
    public final static byte Gamming = 1;
    public final static byte CFB = 2;
    public final static byte MAC = 3;
    private static GOST_algorithm GOST;

    private byte MODE_SELECTED = 0;

    @Override
    public void setKey(byte[] key) {
        if (key.length != 32) throw new GOST_exception("Key length must be 256 bits (32 bytes)!");
        GOST = new GOST_algorithm(key);
    }

    public void setIV(byte[] IV){
        if(IV.length!=8) throw new GOST_exception("IV length must be 64 bits (8 bytes)!");
        GOST.IV = IV;
    }

    public void setMode(byte mode) {
        this.MODE_SELECTED = mode;
    }

    @Override
    public byte[] encrypt(byte[] plain) {
        switch (this.MODE_SELECTED) {
            case 3:
                return GOST.doMac(plain);
            case 2:
                return GOST.encryptInCFB(plain);
            case 1:
                return GOST.encryptInGamming(plain);
            default:
                return GOST.encryptInECB(plain);
        }

    }

    @Override
    public byte[] decrypt(byte[] ciph) {
        switch (this.MODE_SELECTED) {
            case 3:
                throw new GOST_exception("MAC can't be decrypted!");
            case 2:
                return GOST.decryptInCFB(ciph);
            case 1:
                return GOST.decryptInGamming(ciph);
            default:
                return GOST.decryptInECB(ciph);
        }
    }

    @Override
    public void reset() {
        this.MODE_SELECTED = 0;
        GOST = new GOST_algorithm();
    }


    private class GOST_algorithm {
        private final byte[][] S = new byte[][]{
                {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF},
                {0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1},
                {0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF},
                {0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0},
                {0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB},
                {0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC},
                {0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0},
                {0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7},
                {0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2},
        };


        private byte[][] splittedKey = new byte[32][4];
        private byte[] IV = null;

        GOST_algorithm(byte[] K) {
            byte[][] splitted = bitUtil.splitTo4bytes(K);
            for (int i = 0; i < 8; i++) {
                System.arraycopy(splitted[i], 0, splittedKey[i], 0,4);
                System.arraycopy(splitted[i], 0, splittedKey[i+4], 0,4);
                System.arraycopy(splitted[i], 0, splittedKey[i+8], 0,4);
                System.arraycopy(splitted[i], 0, splittedKey[i+12], 0,4);
                System.arraycopy(splitted[i], 0, splittedKey[i+16], 0,4);
                System.arraycopy(splitted[i], 0, splittedKey[32-i-1], 0,4);
            }

        }

        GOST_algorithm() { }



         byte[] encryptInECB(byte[] input) {
            if(input.length % 8 !=0) throw new GOST_exception("In ECB mode input length must be multiple of 8 (64 bits)");
             byte[] encrypted = new byte[input.length];
             for (int i = 0; i < input.length; i+=8) {
                 byte[] chunck = new byte[8];
                 System.arraycopy(input,i,chunck,0,8);
                 byte[] A = new byte[4];
                 byte[] B = new byte[4];
                 System.arraycopy(chunck,0,B,0,4);
                 System.arraycopy(chunck,4, A,0,4);
                 for (int j = 0; j < 32; j++) {
                     byte[] temp = A;
                     A = bitUtil.xor(B,f(A,splittedKey[j]));
                     B = temp;
                 }
                 byte[] e_chuck = new byte[8];
                 System.arraycopy(A,0,e_chuck,0,4);
                 System.arraycopy(B,0,e_chuck,4,4);
                 System.arraycopy(e_chuck,0,encrypted,i,8);
             }
             return encrypted;
        }


        byte[] decryptInECB(byte[] input) {
            if(input.length % 8 !=0) throw new GOST_exception("In ECB mode input length must be multiple of 8 (64 bits)");
            byte[] decrypted = new byte[input.length];
            byte[][] splittedKey_reversed = splittedKey.clone();
            algorithmUtil.reverseMatrix(splittedKey_reversed);
            for (int i = 0; i < input.length; i+=8) {
                byte[] chunck = new byte[8];
                System.arraycopy(input,i,chunck,0,8);
                byte[] A = new byte[4];
                byte[] B = new byte[4];
                System.arraycopy(chunck,0,B,0,4);
                System.arraycopy(chunck,4, A,0,4);
                for (int j = 0; j < 32; j++) {
                    byte[] temp = A;
                    A = bitUtil.xor(B,f(A,splittedKey_reversed[j]));
                    B = temp;
                }
                byte[] d_chuck = new byte[8];
                System.arraycopy(A,0,d_chuck,0,4);
                System.arraycopy(B,0,d_chuck,4,4);
                System.arraycopy(d_chuck,0,decrypted,i,8);
            }
            return decrypted;
        }

         byte[] encryptInCFB(byte[] input) {
            if(this.IV == null) throw new GOST_exception("Initialization Vector is not set! Set it with GOST_89.setIV(byte[] IV)");
            return null;
        }

         byte[] encryptInGamming(byte[] input) {
            if(this.IV == null) throw new GOST_exception("Initialization Vector is not set! Set it with GOST_89.setIV(byte[] IV)");
 return null;
        }

         byte[] doMac(byte[] input) {
            return null;
        }



         byte[] decryptInCFB(byte[] input) {
            return null;
        }

         byte[] decryptInGamming(byte[] input) {
            return null;
        }

         private byte[] f(byte[] A, byte[] Ki){
            byte[] A_Ki = bitUtil.intToByteArray((bitUtil.byteArrayToInt(A) + bitUtil.byteArrayToInt(Ki)));
            A_Ki = bitUtil.splitBy4bits(A_Ki);
            for (int i = 0; i < A_Ki.length; i++) {
                A_Ki[i] = S[i][algorithmUtil.indexOfElement(S[0], (A_Ki[i]))];
            }
            A_Ki = bitUtil.concatBy4bit(A_Ki);
            A_Ki = bitUtil.intToByteArray(bitUtil.rotateL(bitUtil.byteArrayToInt(A_Ki),11));
            return A_Ki;
        }
    }

    private class GOST_exception extends RuntimeException {
        GOST_exception() {
            super();
        }


        GOST_exception(String message) {
            super(message);
        }


    }


}
