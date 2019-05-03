package BlockCiphers;

import Basic.Cipher;
import Basic.algorithmUtil;
import Basic.bitUtil;

import java.util.Arrays;


public class GOST_89 implements Cipher {
    public final static byte ECB = 0;
    public final static byte CTM = 1;
    public final static byte CFB = 2;
    private static GOST_algorithm GOST;

    private byte MODE_SELECTED = 0;

    @Override
    public void setKey(byte[] key) {
        if (key.length != 32) throw new GOST_exception(GOST_exception.KEY_LEN);
        GOST = new GOST_algorithm(key);
    }

    public void setIV(byte[] IV) {
        if (IV.length != 8) throw new GOST_exception(GOST_exception.IV_LEN);
        GOST.IV = IV;
    }

    public void setMode(byte mode) {
        this.MODE_SELECTED = mode;
    }

    @Override
    public byte[] encrypt(byte[] plain) {
        switch (this.MODE_SELECTED) {
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
        private final int C2 = 0x1010101;
        private final int C1 = 0x1010104;
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
                System.arraycopy(splitted[i], 0, splittedKey[i], 0, 4);
                System.arraycopy(splitted[i], 0, splittedKey[i + 4], 0, 4);
                System.arraycopy(splitted[i], 0, splittedKey[i + 8], 0, 4);
                System.arraycopy(splitted[i], 0, splittedKey[i + 12], 0, 4);
                System.arraycopy(splitted[i], 0, splittedKey[i + 16], 0, 4);
                System.arraycopy(splitted[i], 0, splittedKey[32 - i - 1], 0, 4);
            }

        }

        GOST_algorithm() {
        }


        byte[] encryptInECB(byte[] input) {
            if (input.length % 8 != 0) throw new GOST_exception(GOST_exception.DATA_LEN);
            byte[] encrypted = new byte[input.length];
            for (int i = 0; i < input.length; i += 8) {
                byte[] chunck = new byte[8];
                System.arraycopy(input, i, chunck, 0, 8);
                byte[] A = new byte[4];
                byte[] B = new byte[4];
                System.arraycopy(chunck, 0, B, 0, 4);
                System.arraycopy(chunck, 4, A, 0, 4);
                for (int j = 0; j < 32; j++) {
                    byte[] temp = A;
                    A = bitUtil.xor(B, f(A, splittedKey[j]));
                    B = temp;
                }
                byte[] e_chuck = new byte[8];
                System.arraycopy(A, 0, e_chuck, 0, 4);
                System.arraycopy(B, 0, e_chuck, 4, 4);
                System.arraycopy(e_chuck, 0, encrypted, i, 8);
            }
            return encrypted;
        }
        byte[] decryptInECB(byte[] input) {
            if (input.length % 8 != 0) throw new GOST_exception(GOST_exception.DATA_LEN);
            byte[] decrypted = new byte[input.length];
            byte[][] splittedKey_reversed = splittedKey.clone();
            algorithmUtil.reverseMatrix(splittedKey_reversed);
            for (int i = 0; i < input.length; i += 8) {
                byte[] chunck = new byte[8];
                System.arraycopy(input, i, chunck, 0, 8);
                byte[] A = new byte[4];
                byte[] B = new byte[4];
                System.arraycopy(chunck, 0, B, 0, 4);
                System.arraycopy(chunck, 4, A, 0, 4);
                for (int j = 0; j < 32; j++) {
                    byte[] temp = A;
                    A = bitUtil.xor(B, f(A, splittedKey_reversed[j]));
                    B = temp;
                }
                byte[] d_chuck = new byte[8];
                System.arraycopy(A, 0, d_chuck, 0, 4);
                System.arraycopy(B, 0, d_chuck, 4, 4);
                System.arraycopy(d_chuck, 0, decrypted, i, 8);
            }
            return decrypted;
        }


        byte[] encryptInGamming(byte[] input) {
            if (this.IV == null) throw new GOST_exception(GOST_exception.IV_NULL);
            byte[] gamma = generateGamma(this.IV, input.length);
            return bitUtil.xor(input, gamma);
        }

        byte[] decryptInGamming(byte[] input) {
            if (this.IV == null) throw new GOST_exception(GOST_exception.IV_NULL);
            byte[] gamma = generateGamma(this.IV, input.length);
            return bitUtil.xor(input, gamma);
        }


        byte[] encryptInCFB(byte[] input) {
            if (this.IV == null) throw new GOST_exception(GOST_exception.IV_NULL);
            return null;
        }

        byte[] decryptInCFB(byte[] input) {
            if (this.IV == null) throw new GOST_exception(GOST_exception.IV_NULL);
            return null;
        }

        byte[] doMac(byte[] input) {
            return null;
        }

        private byte[] f(byte[] A, byte[] Ki) {
            byte[] A_Ki = bitUtil.intToByteArray((bitUtil.byteArrayToInt(A) + bitUtil.byteArrayToInt(Ki)));
            A_Ki = bitUtil.splitBy4bits(A_Ki);
            for (int i = 0; i < A_Ki.length; i++) {
                A_Ki[i] = S[i][algorithmUtil.binarySearch(S[0], (A_Ki[i]), 0, 16)];
            }
            A_Ki = bitUtil.concatBy4bit(A_Ki);
            A_Ki = bitUtil.intToByteArray(bitUtil.rotateL(bitUtil.byteArrayToInt(A_Ki), 11));
            return A_Ki;
        }

        private byte[] generateGamma(byte[] iv, int len) {
            byte[] iv_clone = encryptInECB(iv);
            byte[] gamma = new byte[len];
            while (len % 8 != 0) len++;
            byte[] gamma_extended = new byte[len];
            byte[] N1 = new byte[4];
            byte[] N2 = new byte[4];
            System.arraycopy(iv_clone, 0, N1, 0, 4);
            System.arraycopy(iv_clone, 4, N2, 0, 4);
            N1 = bitUtil.intToByteArray(bitUtil.byteArrayToInt(N1) + C2);
            N2 = bitUtil.intToByteArray(bitUtil.byteArrayToInt(N2) + C1);
            byte[] gamma_1 = new byte[8];
            System.arraycopy(N1, 0, gamma_1, 0, 4);
            System.arraycopy(N2, 0, gamma_1, 4, 4);
            gamma_1 = encryptInECB(gamma_1);
            System.arraycopy(gamma_1, 0, gamma_extended, 0, 8);

            for (int i = 0; i < len - 8; i += 8) {
                System.arraycopy(gamma_extended, i, N1, 0, 4);
                System.arraycopy(gamma_extended, i + 4, N2, 0, 4);
                N1 = bitUtil.intToByteArray(bitUtil.byteArrayToInt(N1) + C2);
                N2 = bitUtil.intToByteArray(bitUtil.byteArrayToInt(N2) + C1);
                System.arraycopy(N1, 0, gamma_1, 0, 4);
                System.arraycopy(N2, 0, gamma_1, 4, 4);
                gamma_1 = encryptInECB(gamma_1);
                System.arraycopy(gamma_1, 0, gamma_extended, i + 8, 8);
            }
            System.arraycopy(gamma_extended, 0, gamma, 0, gamma.length);
            return gamma;
        }
    }

    private class GOST_exception extends RuntimeException {
        final static String IV_NULL = "Initialization Vector is not set! Set it with GOST_89.setIV(byte[] IV)";
        final static String IV_LEN = "IV length must be 64 bits (8 bytes)!";
        final static String DATA_LEN = "Input length must be multiple of 8 (64 bits)";
        final static String KEY_LEN = "Key length must be 256 bits (32 bytes)!";
        final static String MAC_DEC = "MAC can't be decrypted!";


        GOST_exception() {
            super();
        }


        GOST_exception(String message) {
            super(message);
        }


    }


}




