package Ciphers.BlockCiphers;

import Ciphers.Utils.BitUtil;
import Ciphers.Utils.MathUtil;

class IDEA extends BlockCipher {
    private IDEA_algorithm IDEA_A;

    IDEA() {
        IDEA_A = new IDEA_algorithm();
        super.algorithm = IDEA_A;
        super.KeySize = 16;
        super.IV_Size = 8;
    }


    @Override
    public void setKey(byte[] key) {
        if (key == null || key.length != getKeySize())
            throw new BlockCipherException(BlockCipherException.KEY_LEN, 128, 16);
        byte[] IV_save = IDEA_A == null ? null : IDEA_A.IV;
        IDEA_A = new IDEA_algorithm(key);
        IDEA_A.IV = IV_save;
        super.algorithm = IDEA_A;
    }


    private class IDEA_algorithm extends BlockCipherAlgorithm {
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


        @Override
        byte[] encryptInECB(byte[] input) {
            byte[] encrypted = input.clone();
            for (int k = 0; k < encrypted.length; k += blocksize) {
                byte[] chunck = new byte[blocksize];
                System.arraycopy(encrypted, k, chunck, 0, blocksize);
                short[] input_16 = BitUtil.ByteArrays.byteArrayToShortArray(chunck);
                int[] D_16 = new int[input_16.length];
                int copy_counter;
                for (copy_counter = 0; copy_counter < input_16.length; copy_counter++) {
                    D_16[copy_counter] = input_16[copy_counter];
                }
                for (int i = 0; i < 8; i++) {
                    ENC_round(D_16, i);
                }
                int D_16_1 = D_16[1];
                D_16[0] = MathUtil.Operation.Multiply_16(D_16[0], KEY_TABLE_LAST[0]);
                D_16[1] = MathUtil.Operation.Add_16(D_16[2], KEY_TABLE_LAST[1]);
                D_16[2] = MathUtil.Operation.Add_16(D_16_1, KEY_TABLE_LAST[2]);
                D_16[3] = MathUtil.Operation.Multiply_16(D_16[3], KEY_TABLE_LAST[3]);


                byte[] encrypted_full = BitUtil.ByteArrays.intArrayToByteArray(D_16);
                byte[] encrypted_m = new byte[encrypted_full.length / 2];
                for (int i = 2, e = 0; i < encrypted_full.length; i += 2) {
                    encrypted_m[e] = encrypted_full[i];
                    encrypted_m[e + 1] = encrypted_full[i + 1];
                    e += 2;
                    i += 2;
                }
                System.arraycopy(encrypted_m, 0, encrypted, k, blocksize);
            }


            return encrypted;
        }


        @Override
        byte[] decryptInECB(byte[] input) {
            if (input.length % blocksize != 0) throw new BlockCipherException(BlockCipherException.DATA_LEN, blocksize);
            byte[] decrypted = input.clone();
            for (int k = 0; k < decrypted.length; k += blocksize) {
                byte[] chunck = new byte[blocksize];
                System.arraycopy(decrypted, k, chunck, 0, blocksize);
                short[] input_16 = BitUtil.ByteArrays.byteArrayToShortArray(chunck);
                int[] D_16 = new int[input_16.length];
                int copy_counter;
                for (copy_counter = 0; copy_counter < input_16.length; copy_counter++) {
                    D_16[copy_counter] = input_16[copy_counter];
                }
                for (int i = 0; i < 8; i++) {
                    DEC_round(D_16, i);
                }
                int D_16_1 = D_16[1];
                D_16[0] = MathUtil.Operation.Multiply_16(D_16[0], DKEY_TABLE_LAST[0]);
                D_16[1] = MathUtil.Operation.Add_16(D_16[2], DKEY_TABLE_LAST[1]);
                D_16[2] = MathUtil.Operation.Add_16(D_16_1, DKEY_TABLE_LAST[2]);
                D_16[3] = MathUtil.Operation.Multiply_16(D_16[3], DKEY_TABLE_LAST[3]);


                byte[] decrypted_full = BitUtil.ByteArrays.intArrayToByteArray(D_16);
                byte[] decrypted_m = new byte[decrypted_full.length / 2];
                for (int i = 2, e = 0; i < decrypted_full.length; i += 2) {
                    decrypted_m[e] = decrypted_full[i];
                    decrypted_m[e + 1] = decrypted_full[i + 1];
                    e += 2;
                    i += 2;


                }
                System.arraycopy(decrypted_m, 0, decrypted, k, blocksize);
            }


            return decrypted;


        }

        int[] ENC_round(int[] Di, int round) {
            int A, B, C, D, E, F;
            A = MathUtil.Operation.Multiply_16(Di[0], KEY_TABLE[round][0]);
            B = MathUtil.Operation.Add_16(Di[1], KEY_TABLE[round][1]);
            C = MathUtil.Operation.Add_16(Di[2], KEY_TABLE[round][2]);
            D = MathUtil.Operation.Multiply_16(Di[3], KEY_TABLE[round][3]);
            E = (A ^ C) & 0xFFFF;
            F = (B ^ D) & 0xFFFF;

            int F1 = MathUtil.Operation.Multiply_16(KEY_TABLE[round][5], MathUtil.Operation.Add_16(F, MathUtil.Operation.Multiply_16(E, KEY_TABLE[round][4])));
            int F2 = MathUtil.Operation.Add_16(MathUtil.Operation.Multiply_16(E, KEY_TABLE[round][4]), F1);
            Di[0] = (A ^ F1) & 0xFFFF;
            Di[1] = (C ^ F1) & 0xFFFF;
            Di[2] = (B ^ F2) & 0xFFFF;
            Di[3] = (D ^ F2) & 0xFFFF;
            return Di;
        }

        int[] DEC_round(int[] Di, int round) {
            int A, B, C, D, E, F;
            A = MathUtil.Operation.Multiply_16(Di[0], DKEY_TABLE[round][0]);
            B = MathUtil.Operation.Add_16(Di[1], DKEY_TABLE[round][1]);
            C = MathUtil.Operation.Add_16(Di[2], DKEY_TABLE[round][2]);
            D = MathUtil.Operation.Multiply_16(Di[3], DKEY_TABLE[round][3]);
            E = (A ^ C) & 0xFFFF;
            F = (B ^ D) & 0xFFFF;

            int F1 = MathUtil.Operation.Multiply_16(DKEY_TABLE[round][5], MathUtil.Operation.Add_16(F, MathUtil.Operation.Multiply_16(E, DKEY_TABLE[round][4])));
            int F2 = MathUtil.Operation.Add_16(MathUtil.Operation.Multiply_16(E, DKEY_TABLE[round][4]), F1);
            Di[0] = (A ^ F1) & 0xFFFF;
            Di[1] = (C ^ F1) & 0xFFFF;
            Di[2] = (B ^ F2) & 0xFFFF;
            Di[3] = (D ^ F2) & 0xFFFF;
            return Di;
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

            for (int i = 0; i < 7; i++, j += 8) {
                bytes = BitUtil.Rotation.rotate128L(bytes.clone(), 25);
                short[] tmp = BitUtil.ByteArrays.byteArrayToShortArray(bytes);
                System.arraycopy(tmp, 0, subkeys, j, 8);
                System.arraycopy(subkeys, j - k, subkeys6[h++], 0, 6);
                k += 2;
                if (i == 6) {
                    tmp = BitUtil.ByteArrays.byteArrayToShortArray(BitUtil.Rotation.rotate128R(bytes, 25));
                    System.arraycopy(tmp, 0, last, 0, 4);
                }
            }


            for (int i = 0; i < 8; i++) {
                for (int l = 0; l < 6; l++) {
                    KEY_TABLE[i][l] = ((int) subkeys6[i][l]) & 0xffff;
                }
            }

            for (int i = 0; i < 4; i++) {
                KEY_TABLE_LAST[i] = ((int) last[i]) & 0xffff;
            }


        }

        private void generateDecryptionKeys() {
            int j = 7;
            DKEY_TABLE[0][0] = MathUtil.Operation.MultiplicativeInverse(KEY_TABLE_LAST[0], 65537);
            DKEY_TABLE[0][1] = MathUtil.Operation.AdditiveInverse(KEY_TABLE_LAST[1], 65536);
            DKEY_TABLE[0][2] = MathUtil.Operation.AdditiveInverse(KEY_TABLE_LAST[2], 65536);
            DKEY_TABLE[0][3] = MathUtil.Operation.MultiplicativeInverse(KEY_TABLE_LAST[3], 65537);
            DKEY_TABLE[0][4] = KEY_TABLE[7][4];
            DKEY_TABLE[0][5] = KEY_TABLE[7][5];

            for (int i = 1; i < 8; i++) {
                DKEY_TABLE[i][0] = MathUtil.Operation.MultiplicativeInverse(KEY_TABLE[j][0], 65537);
                DKEY_TABLE[i][1] = MathUtil.Operation.AdditiveInverse(KEY_TABLE[j][2], 65536);
                DKEY_TABLE[i][2] = MathUtil.Operation.AdditiveInverse(KEY_TABLE[j][1], 65536);
                DKEY_TABLE[i][3] = MathUtil.Operation.MultiplicativeInverse(KEY_TABLE[j][3], 65537);
                j--;
                DKEY_TABLE[i][4] = KEY_TABLE[j][4];
                DKEY_TABLE[i][5] = KEY_TABLE[j][5];
                if (j == 0) {
                    DKEY_TABLE_LAST[0] = MathUtil.Operation.MultiplicativeInverse(KEY_TABLE[0][0], 65537);
                    DKEY_TABLE_LAST[1] = MathUtil.Operation.AdditiveInverse(KEY_TABLE[0][1], 65536);
                    DKEY_TABLE_LAST[2] = MathUtil.Operation.AdditiveInverse(KEY_TABLE[0][2], 65536);
                    DKEY_TABLE_LAST[3] = MathUtil.Operation.MultiplicativeInverse(KEY_TABLE[0][3], 65537);

                }
            }

        }


    }
}
