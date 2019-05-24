package Ciphers.BlockCiphers;

import Ciphers.Utils.BitUtil;

public class IDEA extends BlockCipher {
    private IDEA_algorithm IDEA_A;


    IDEA() {
        IDEA_A = new IDEA_algorithm();
        super.algorithm = IDEA_A;
        super.KeySize = 16;
        super.IV_Size = 8;
    }


    @Override
    public void setKey(byte[] key) {
        if (key == null || key.length != 16) throw new BlockCipherException(BlockCipherException.KEY_LEN, 128, 16);
        byte[] IV_save = IDEA_A == null ? null : IDEA_A.IV;
        IDEA_A = new IDEA_algorithm(key);
        IDEA_A.IV = IV_save;
        super.algorithm = IDEA_A;
    }


    private class IDEA_algorithm extends BlockCipherAlgorithm {
        static final int Add = 65536;
        static final int Mul = 65537;
        private int[][] KEY_TABLE = new int[8][6];
        private int[] KEY_TABLE_LAST = new int[4];
        private int[][] DKEY_TABLE = new int[8][6];
        private int[] DKEY_TABLE_LAST = new int[4];

        IDEA_algorithm() {
            super();
        }


        IDEA_algorithm(byte[] key) {
            super();
            generateEncryptionKeys(key);
            generateDecryptionKeys();

        }

        //TODO Implement ECB encryption
        @Override
        byte[] encryptInECB(byte[] input) {
            if (input.length % 8 != 0) throw new BlockCipherException(BlockCipherException.DATA_LEN, 8);
            return null;

        }


        //TODO Implement ECB decryption
        @Override
        byte[] decryptInECB(byte[] input) {
            if (input.length % 8 != 0) throw new BlockCipherException(BlockCipherException.DATA_LEN, 8);
            return null;

        }


        private void generateEncryptionKeys(byte[] key) {
            byte[] bytes = key.clone();
            short[] subkeys = new short[64];
            short[] key_6 = BitUtil.ByteArrays.byteArrayToShortArray(bytes);

            System.arraycopy(key_6, 0, subkeys, 0, 8);
            short[][] subkeys6 = new short[8][6];

            short[] last = new short[4];
            System.arraycopy(key_6, 0, subkeys6[0], 0, 6);

            int j = 8;
            int h = 1;
            int k = 2;

            for (int i = 0; i < 52; i += 8, j += 8) {
                bytes = BitUtil.Rotation.rotate128L(bytes, 25);
                short[] tmp = BitUtil.ByteArrays.byteArrayToShortArray(bytes);
                System.arraycopy(tmp, 0, subkeys, j, 8);
                System.arraycopy(subkeys, j - k, subkeys6[h++], 0, 6);
                k += 2;
                if (i == 48) {
                    tmp = BitUtil.ByteArrays.byteArrayToShortArray(BitUtil.Rotation.rotate128R(bytes, 25));
                    System.arraycopy(tmp, 0, last, 0, 4);
                }
            }


            for (int i = 0; i < 8; i++) {
                for (int l = 0; l < 6; l++) {
                    KEY_TABLE[i][l] = subkeys6[i][l];
                    KEY_TABLE[i][l] &= 0xffff;
                }
            }

            for (int i = 0; i < 4; i++) {
                KEY_TABLE_LAST[i] = last[i];
                KEY_TABLE_LAST[i] &= 0xffff;
            }

        }

        private void generateDecryptionKeys() {
            int j = 7;
            int[][] DEC_subkeys6 = new int[8][6];
            int[] DEC_last = new int[4];
            DEC_subkeys6[0][0] = BitUtil.Operation.mInver(KEY_TABLE_LAST[0], 65537);
            DEC_subkeys6[0][1] = BitUtil.Operation.addInver(KEY_TABLE_LAST[1], 65536);
            DEC_subkeys6[0][2] = BitUtil.Operation.addInver(KEY_TABLE_LAST[2], 65536);
            DEC_subkeys6[0][3] = BitUtil.Operation.mInver(KEY_TABLE_LAST[3], 65537);
            DEC_subkeys6[0][4] = KEY_TABLE[7][4];
            DEC_subkeys6[0][5] = KEY_TABLE[7][5];

            for (int i = 1; i < 8; i++) {
                DEC_subkeys6[i][0] = BitUtil.Operation.mInver(KEY_TABLE[j][0], 65537);
                DEC_subkeys6[i][1] = BitUtil.Operation.addInver(KEY_TABLE[j][2], 65536);
                DEC_subkeys6[i][2] = BitUtil.Operation.addInver(KEY_TABLE[j][1], 65536);
                DEC_subkeys6[i][3] = BitUtil.Operation.mInver(KEY_TABLE[j][3], 65537);
                j--;
                DEC_subkeys6[i][4] = KEY_TABLE[j][4];
                DEC_subkeys6[i][5] = KEY_TABLE[j][5];

            }

            DEC_last[0] = BitUtil.Operation.mInver(KEY_TABLE[0][0], 65537);
            DEC_last[1] = BitUtil.Operation.addInver(KEY_TABLE[0][1], 65536);
            DEC_last[2] = BitUtil.Operation.addInver(KEY_TABLE[0][2], 65536);
            DEC_last[3] = BitUtil.Operation.mInver(KEY_TABLE[0][3], 65537);


            DKEY_TABLE = DEC_subkeys6;
            DKEY_TABLE_LAST = DEC_last;
        }


    }
}
