package Ciphers.BlockCiphers;

import Ciphers.Utils.BitUtil;


class TEA extends BlockCipher {
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
        private int K0, K1, K2, K3 = 0;

        TEA_algoritm() {
            super();
        }

        TEA_algoritm(byte[] key) {
            super();
            byte[] K0_B = new byte[4];
            byte[] K1_B = new byte[4];
            byte[] K2_B = new byte[4];
            byte[] K3_B = new byte[4];

            System.arraycopy(key, 0, K0_B, 0, 4);
            System.arraycopy(key, 4, K1_B, 0, 4);
            System.arraycopy(key, 8, K2_B, 0, 4);
            System.arraycopy(key, 12, K3_B, 0, 4);

            this.K0 = BitUtil.ByteArrays.byteArrayToInt(K0_B);
            this.K1 = BitUtil.ByteArrays.byteArrayToInt(K1_B);
            this.K2 = BitUtil.ByteArrays.byteArrayToInt(K2_B);
            this.K3 = BitUtil.ByteArrays.byteArrayToInt(K3_B);
        }

        @Override
        byte[] encryptInECB(byte[] input) {

            if (input.length % 8 != 0) throw new BlockCipherException(BlockCipherException.DATA_LEN, 8);
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
            if (input.length % 8 != 0) throw new BlockCipherException(BlockCipherException.DATA_LEN, 8);
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
