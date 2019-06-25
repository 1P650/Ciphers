package Ciphers.BlockCiphers;

import Ciphers.Utils.AlgorithmUtil;
import Ciphers.Utils.BitUtil;
public class GOST89 extends BlockCipher {
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
        private final int C1 = 0x1010104;
        private final int C2 = 0x1010101;
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
        int[] e_key = new int[32];

        GOST89_algorithm() {
            super();
        }

        GOST89_algorithm(byte[] key) {
            super();
            int[] key_32_t = BitUtil.ByteArrays.byteArrayToIntArray(key);
            System.arraycopy(key_32_t, 0, e_key, 0, 8);
            System.arraycopy(key_32_t, 0, e_key, 8, 8);
            System.arraycopy(key_32_t, 0, e_key, 16, 8);
            AlgorithmUtil.reverseArray(key_32_t);
            System.arraycopy(key_32_t, 0, e_key, 24, 8);
        }

        @Override
        byte[] encryptInECB(byte[] input) {
            int[] encrypted = BitUtil.ByteArrays.byteArrayToIntArray(input);
            for (int k = 0; k < encrypted.length; k+=2) {
                int[] chunck = new int[2];
                System.arraycopy(encrypted,k,chunck,0,2);
                int B = chunck[1];
                int A = chunck[0];
                for (int i = 0; i < 32; i++) {
                    int temp = B;
                    B = A ^ F(B, e_key[i]);
                    A = temp;
                }
                System.arraycopy(new int[]{B,A}, 0, encrypted, k,2);
            }

            return BitUtil.ByteArrays.intArrayToByteArray(encrypted);
        }

        @Override
        byte[] decryptInECB(byte[] input) {
            int[] decrypted = BitUtil.ByteArrays.byteArrayToIntArray(input);
            for (int k = 0; k < decrypted.length; k+=2) {
                int[] chunck = new int[2];
                System.arraycopy(decrypted, k, chunck, 0, 2);
                int B = chunck[1];
                int A = chunck[0];
                for (int i = 31; i >= 0; i--) {
                    int temp = B;
                    B = A ^ F(B, e_key[i]);
                    A = temp;
                }
                System.arraycopy(new int[]{B,A}, 0, decrypted, k,2);
            }
            return BitUtil.ByteArrays.intArrayToByteArray(decrypted);
        }

        @Override
        byte[] encryptInCTR(byte[] input) {
            if (this.IV == null) throw new BlockCipherException(BlockCipherException.IV_NULL);
            byte[] gamma = generateGamma(this.IV, input.length);
            return BitUtil.Operation.XOR(input, gamma);
        }

        @Override
        byte[] decryptInCTR(byte[] input) {
            if (this.IV == null) throw new BlockCipherException(BlockCipherException.IV_NULL);
            byte[] gamma = generateGamma(this.IV, input.length);
            return BitUtil.Operation.XOR(input, gamma);
        }

        private byte[] encryptInECB16(byte[] mac) {
            int[] encrypted = BitUtil.ByteArrays.byteArrayToIntArray(mac);
            for (int k = 0; k < encrypted.length; k+=2) {
                int[] chunck = new int[2];
                System.arraycopy(encrypted,k,chunck,0,2);
                int B = chunck[1];
                int A = chunck[0];
                for (int i = 0; i < 16; i++) {
                    int temp = B;
                    B = A ^ F(B, e_key[i]);
                    A = temp;
                }
                System.arraycopy(new int[]{B,A}, 0, encrypted, k,2);
            }

            return BitUtil.ByteArrays.intArrayToByteArray(encrypted);
        }

        private byte[] generateGamma(byte[] iv, int len) {
            byte[] iv_clone = encryptInECB(iv);
            int [] iv_32 = BitUtil.ByteArrays.byteArrayToIntArray(iv_clone);
            byte[] gamma_extended = new byte[BitUtil.Extend.extendToSize(len, 8)];
            int N1 = iv_32[0];
            int N2 = iv_32[1];
            byte[] gamma_1 = gamma_round(N1, N2);
            System.arraycopy(gamma_1, 0, gamma_extended, 0, 8);
            for (int i = 0; i < len; i += 8) {
                byte[] N_b = new byte[8];
                System.arraycopy(gamma_extended, i, N_b, 0, 4);
                System.arraycopy(gamma_extended, i + 4, N_b, 4, 4);
                int[] N = BitUtil.ByteArrays.byteArrayToIntArray(N_b);
                N1 = N[0];
                N2 = N[1];
                gamma_1 = gamma_round(N1, N2);
                System.arraycopy(gamma_1, 0, gamma_extended, i, 8);
            }

            byte[] gamma = new byte[len];
            System.arraycopy(gamma_extended, 0, gamma, 0, gamma.length);
            return gamma;
        }
        private byte[] gamma_round(int N1, int N2) {
            N1 = N1 + C2;
            N2 = N2 + C1;
            return encryptInECB(BitUtil.ByteArrays.intArrayToByteArray(new int[]{N1,N2}));

        }

        private int F(int A, int Ki) {
            int A_Ki = A + Ki;
            byte[] A_4 = BitUtil.Fission.splitBy4bits(BitUtil.ByteArrays.intToByteArray(A_Ki));
            for (int i = 7, j = 1; i >= 0; i--) A_4[i] = S[j++][A_4[i] & 0xFF];
            A_Ki = BitUtil.ByteArrays.byteArrayToInt(BitUtil.Fission.concatBy4bit(A_4));
            A_Ki = BitUtil.Rotation.rotateL(A_Ki, 11);
            return A_Ki;
        }

        private byte[] MAC(byte[] input){
            byte[] input_extended;
            if (input.length % blocksize != 0) {
                input_extended = new byte[BitUtil.Extend.extendToSize(input.length, blocksize)];
                System.arraycopy(input, 0, input_extended, 0, input.length);
            } else {
                input_extended = input.clone();
            }
            byte[] MAC = new byte[blocksize];
            System.arraycopy(input_extended, 0, MAC, 0, blocksize);
            BitUtil.Print.printHex(MAC);
            for (int i = 0; i < input_extended.length; i += blocksize) {
                MAC = encryptInECB16(MAC);
                byte[] chunck = new byte[blocksize];
                System.arraycopy(input_extended, i, chunck, 0, blocksize);
                MAC = BitUtil.Operation.XOR(MAC, chunck);
            }

            return MAC;
        }


    }
}

