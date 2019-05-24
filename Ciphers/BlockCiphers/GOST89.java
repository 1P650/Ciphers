package Ciphers.BlockCiphers;

import Ciphers.Utils.AlgorithmUtil;
import Ciphers.Utils.BitUtil;


class GOST89 extends BlockCipher {
    private GOST89_algorithm GOST89_A;

    GOST89() {
        GOST89_A = new GOST89_algorithm();
        super.algorithm = GOST89_A;
        super.KeySize = 32;
        super.IV_Size = 8;
    }


    @Override
    public void setKey(byte[] key) {
        if (key == null || key.length != 32) throw new BlockCipherException(BlockCipherException.KEY_LEN, 256, 32);
        byte[] IV_save = GOST89_A == null ? null : GOST89_A.IV;
        GOST89_A = new GOST89_algorithm(key);
        GOST89_A.IV = IV_save;
        super.algorithm = GOST89_A;
    }


    @Override
    public byte[] MAC(byte[] input) {
        return GOST89_A.MAC(input);
    }


    private class GOST89_algorithm extends BlockCipher.BlockCipherAlgorithm {
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

        GOST89_algorithm() {
            super.blocksize = 8;
        }

        GOST89_algorithm(byte[] key) {
            byte[][] splitted = BitUtil.Fission.splitTo4bytes(key);
            for (int i = 0; i < 8; i++) {
                System.arraycopy(splitted[i], 0, splittedKey[i], 0, 4);
                System.arraycopy(splitted[i], 0, splittedKey[i + 4], 0, 4);
                System.arraycopy(splitted[i], 0, splittedKey[i + 8], 0, 4);
                System.arraycopy(splitted[i], 0, splittedKey[i + 12], 0, 4);
                System.arraycopy(splitted[i], 0, splittedKey[i + 16], 0, 4);
                System.arraycopy(splitted[i], 0, splittedKey[32 - i - 1], 0, 4);
            }


        }


        @Override
        byte[] encryptInECB(byte[] input) {
            if (input.length % blocksize != 0) throw new BlockCipherException(BlockCipherException.DATA_LEN, 8);

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
                    A = BitUtil.Operation.Xor(B, f(A, splittedKey[j]));
                    B = temp;
                }
                byte[] e_chuck = new byte[8];
                System.arraycopy(A, 0, e_chuck, 0, 4);
                System.arraycopy(B, 0, e_chuck, 4, 4);
                System.arraycopy(e_chuck, 0, encrypted, i, 8);
            }
            return encrypted;
        }

        @Override
        byte[] decryptInECB(byte[] input) {
            if (input.length % blocksize != 0) throw new BlockCipherException(BlockCipherException.DATA_LEN);

            byte[] decrypted = new byte[input.length];
            byte[][] splittedKey_reversed = splittedKey.clone();
            AlgorithmUtil.reverseMatrix(splittedKey_reversed);

            for (int i = 0; i < input.length; i += 8) {

                byte[] chunck = new byte[8];
                System.arraycopy(input, i, chunck, 0, 8);

                byte[] A = new byte[4];
                byte[] B = new byte[4];

                System.arraycopy(chunck, 0, B, 0, 4);
                System.arraycopy(chunck, 4, A, 0, 4);

                for (int j = 0; j < 32; j++) {
                    byte[] temp = A;
                    A = BitUtil.Operation.Xor(B, f(A, splittedKey_reversed[j]));
                    B = temp;
                }

                byte[] d_chuck = new byte[8];

                System.arraycopy(A, 0, d_chuck, 0, 4);
                System.arraycopy(B, 0, d_chuck, 4, 4);
                System.arraycopy(d_chuck, 0, decrypted, i, 8);
            }

            return decrypted;
        }

        @Override
        byte[] encryptInCBC(byte[] input) {
            throw new BlockCipherException("In GOST89 this mode is not allowed!");
        }

        @Override
        byte[] decryptInCBC(byte[] input) {
            throw new BlockCipherException("In GOST89 this mode is not allowed!");
        }

        @Override
        byte[] decryptInOFB(byte[] input) {
            throw new BlockCipherException("In GOST89 this mode is not allowed!");
        }

        @Override
        byte[] encryptInOFB(byte[] input) {
            throw new BlockCipherException("In GOST89 this mode is not allowed!");
        }

        @Override
        byte[] encryptInCTR(byte[] input) {
            if (this.IV == null) throw new BlockCipherException(BlockCipherException.IV_NULL, "GOST89");
            byte[] gamma = generateGamma(this.IV, input.length);
            return BitUtil.Operation.Xor(input, gamma);
        }

        @Override
        byte[] decryptInCTR(byte[] input) {
            if (this.IV == null) throw new BlockCipherException(BlockCipherException.IV_NULL, "GOST89");
            byte[] gamma = generateGamma(this.IV, input.length);
            return BitUtil.Operation.Xor(input, gamma);
        }


        byte[] MAC(byte[] input) {
            byte[] input_extended;
            if (input.length % blocksize != 0) {
                input_extended = new byte[BitUtil.Extend.extendToSize(input.length, blocksize)];
                System.arraycopy(input, 0, input_extended, 0, input.length);
            } else {
                input_extended = input.clone();
            }
            byte[] MAC = new byte[blocksize];
            System.arraycopy(input_extended, 0, MAC, 0, blocksize);
            for (int i = 8; i < input_extended.length - blocksize; i += blocksize) {
                MAC = encryptInECB16(MAC);
                byte[] chunck = new byte[blocksize];
                System.arraycopy(input_extended, i, chunck, 0, blocksize);
                BitUtil.Operation.Xor(MAC, chunck);
            }
            return MAC;
        }

        private byte[] encryptInECB16(byte[] input) {
            if (input.length % 8 != 0) throw new BlockCipherException(BlockCipherException.DATA_LEN, 64, 8);
            byte[] encrypted = new byte[input.length];
            for (int i = 0; i < input.length; i += 8) {
                byte[] chunck = new byte[8];
                System.arraycopy(input, i, chunck, 0, 8);
                byte[] A = new byte[4];
                byte[] B = new byte[4];
                System.arraycopy(chunck, 0, B, 0, 4);
                System.arraycopy(chunck, 4, A, 0, 4);
                for (int j = 0; j < 16; j++) {
                    byte[] temp = A;
                    A = BitUtil.Operation.Xor(B, f(A, splittedKey[j]));
                    B = temp;
                }
                byte[] e_chuck = new byte[8];
                System.arraycopy(A, 0, e_chuck, 0, 4);
                System.arraycopy(B, 0, e_chuck, 4, 4);
                System.arraycopy(e_chuck, 0, encrypted, i, 8);
            }
            return encrypted;
        }

        private byte[] f(byte[] A, byte[] Ki) {
            byte[] A_Ki = BitUtil.ByteArrays.intToByteArray((BitUtil.ByteArrays.byteArrayToInt(A) + BitUtil.ByteArrays.byteArrayToInt(Ki)));
            A_Ki = BitUtil.Fission.splitBy4bits(A_Ki);
            for (int i = 0; i < A_Ki.length; i++) {
                A_Ki[i] = S[i][AlgorithmUtil.binarySearch(S[0], (A_Ki[i]), 0, 16)];
            }
            A_Ki = BitUtil.Fission.concatBy4bit(A_Ki);
            A_Ki = BitUtil.ByteArrays.intToByteArray(BitUtil.Rotation.rotateL(BitUtil.ByteArrays.byteArrayToInt(A_Ki), 11));
            return A_Ki;
        }

        private byte[] generateGamma(byte[] iv, int len) {
            byte[] iv_clone = encryptInECB(iv);
            byte[] gamma_extended = new byte[BitUtil.Extend.extendToSize(len, 8)];
            byte[] N1 = new byte[4];
            byte[] N2 = new byte[4];
            System.arraycopy(iv_clone, 0, N1, 0, 4);
            byte[] gamma_1 = gamma_round(N1, N2);
            System.arraycopy(gamma_1, 0, gamma_extended, 0, 8);

            for (int i = 0; i < len; i += 8) {
                System.arraycopy(gamma_extended, i, N1, 0, 4);
                System.arraycopy(gamma_extended, i + 4, N2, 0, 4);
                gamma_1 = gamma_round(N1, N2);
                System.arraycopy(gamma_1, 0, gamma_extended, i, 8);
            }

            byte[] gamma = new byte[len];
            System.arraycopy(gamma_extended, 0, gamma, 0, gamma.length);
            return gamma;
        }

        private byte[] gamma_round(byte[] N1, byte[] N2) {
            byte[] gamma = new byte[8];
            N1 = BitUtil.ByteArrays.intToByteArray(BitUtil.ByteArrays.byteArrayToInt(N1) + C2);
            N2 = BitUtil.ByteArrays.intToByteArray(BitUtil.ByteArrays.byteArrayToInt(N2) + C1);
            System.arraycopy(N1, 0, gamma, 0, 4);
            System.arraycopy(N2, 0, gamma, 4, 4);
            gamma = encryptInECB(gamma);
            return gamma;

        }
    }
}
