package Ciphers.BlockCiphers;

import Ciphers.Utils.BitUtil;


class TEA extends BlockCipher {
    private final int[] KEY_SIZES = new int[]{4, 56};
    private TEA_algoritm TEA_A;

    TEA() {
        TEA_A = new TEA_algoritm();
        super.algorithm = TEA_A;
        super.KeySize = 16;
        super.IV_Size = 8;

    }

    @Override
    public void setKey(byte[] key) {
        if (key == null || key.length != 16) throw new BlockCipherException(BlockCipherException.KEY_LEN, 128, 16);
        byte[] IV_save = TEA_A == null ? null : TEA_A.IV;
        TEA_A = new TEA_algoritm(key);
        TEA_A.IV = IV_save;
        super.algorithm = TEA_A;
    }


    private class TEA_algoritm extends BlockCipherAlgorithm {
        private int DELTA_E = 0x9e3779b9;
        private int DELTA_D = 0xc6ef3720;
        private int K0, K1, K2, K3;

        TEA_algoritm() {
            super();
        }

        TEA_algoritm(byte[] key) {
            super();
            int[] K_T = BitUtil.ByteArrays.byteArrayToIntArray(key);
            this.K0 = K_T[0];
            this.K1 = K_T[1];
            this.K2 = K_T[2];
            this.K3 = K_T[3];
        }

        @Override
        byte[] encryptInECB(byte[] input) {
            int[] plain_32 = BitUtil.ByteArrays.byteArrayToIntArray(input);
            for (int k = 0; k < plain_32.length - 1; k += 2) {
                int L = plain_32[k];
                int R = plain_32[k + 1];
                int delta_e = 0;
                for (int i = 0; i < 32; i++) {
                    delta_e += DELTA_E;
                    L += ((R << 4) + K0) ^ (R + delta_e) ^ ((R >> 5) + K1);
                    R += ((L << 4) + K2) ^ (L + delta_e) ^ ((L >> 5) + K3);
                }
                plain_32[k] = L;
                plain_32[k + 1] = R;
            }
            return BitUtil.ByteArrays.intArrayToByteArray(plain_32);

        }

        @Override
        byte[] decryptInECB(byte[] input) {
            int[] plain_32 = BitUtil.ByteArrays.byteArrayToIntArray(input);
            for (int k = 0; k < plain_32.length - 1; k += 2) {
                int L = plain_32[k];
                int R = plain_32[k + 1];
                int delta_d = DELTA_D;
                for (int i = 0; i < 32; i++) {
                    R -= ((L << 4) + K2) ^ (L + delta_d) ^ ((L >> 5) + K3);
                    L -= ((R << 4) + K0) ^ (R + delta_d) ^ ((R >> 5) + K1);
                    delta_d -= DELTA_E;
                }
                plain_32[k] = L;
                plain_32[k + 1] = R;
            }


            return BitUtil.ByteArrays.intArrayToByteArray(plain_32);
        }

    }


}
