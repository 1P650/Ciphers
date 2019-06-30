package Ciphers.StreamCiphers;

import Ciphers.Utils.BitUtil;

class Rabbit extends StreamCipher {
    private Rabbit_algorithm RABBIT_A;

    Rabbit() {
        RABBIT_A = new Rabbit_algorithm();
        super.algorithm = RABBIT_A;
        super.KeySize = 16;
        super.IV_Size = 8;

    }

    @Override
    public void setKey(byte[] key) {
        if (key == null || key.length != getKeySize())
            throw new StreamCipherExeption(StreamCipherExeption.KEY_LEN, 128, 16);
        RABBIT_A = new Rabbit_algorithm(key);
        super.algorithm = RABBIT_A;
    }

    @Override
    public void setIV(byte[] IV) {
        super.setIV(IV);
        if (RABBIT_A.IV != null) {
            RABBIT_A.initByIV(RABBIT_A.IV);
        }
    }

    private class Rabbit_algorithm extends StreamCipher.StreamCipherAlgorithm {
        private int[] X = null;
        private int[] C = null;
        private int[] A = new int[]{0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3};
        private byte b;

        Rabbit_algorithm() {
            b = 0;
        }

        Rabbit_algorithm(byte[] key) {
            b = 0;
            initByKey(key);
        }

        private void initByKey(byte[] key) {
            X = new int[8];
            C = new int[8];
            short[] k = BitUtil.ByteArrays.byteArrayToShortArray(key);
            for (int j = 0; j < 8; j++) {
                if ((j & 1) == 0) {
                    X[j] = ((k[(j + 1) & 0x7]) << 16) | k[j] & 0xFFFF;
                    C[j] = ((k[(j + 4) & 0x7]) << 16) | k[(j + 5) & 0x7] & 0xFFFF;
                } else {
                    X[j] = ((k[(j + 5) & 0x7]) << 16) | k[(j + 4) & 0x7] & 0xFFFF;
                    C[j] = (k[j] << 16) | k[(j + 1) & 0x7] & 0xFFFF;
                }
            }


            for (int i = 0; i < 4; i++) {
                nextState();
            }
            C[0] ^= X[4];
            C[1] ^= X[5];
            C[2] ^= X[6];
            C[3] ^= X[7];
            C[4] ^= X[0];
            C[5] ^= X[1];
            C[6] ^= X[2];
            C[7] ^= X[3];
        }


        void initByIV(byte[] IV) {
            if (X == null || C == null) throw new StreamCipherExeption("Set up key before IV!");
            short[] IV_16 = BitUtil.ByteArrays.byteArrayToShortArray(IV);
            C[0] ^= IV_16[1] << 16 | IV_16[0] & 0xffff;
            C[1] ^= IV_16[3] << 16 | IV_16[1] & 0xffff;
            C[2] ^= IV_16[3] << 16 | IV_16[2] & 0xffff;
            C[3] ^= IV_16[2] << 16 | IV_16[0] & 0xffff;
            C[4] ^= IV_16[1] << 16 | IV_16[0] & 0xffff;
            C[5] ^= IV_16[3] << 16 | IV_16[1] & 0xffff;
            C[6] ^= IV_16[3] << 16 | IV_16[2] & 0xffff;
            C[7] ^= IV_16[2] << 16 | IV_16[0] & 0xffff;

            for (int i = 0; i < 4; i++) {
                nextState();
            }
        }


        private void nextState() {
            counterUpdate();
            int[] G = new int[8];
            for (int j = 0; j < 8; j++) {
                G[j] = g(X[j], C[j]);
            }
            X[0] = (int) (G[0] + BitUtil.Rotation.rotateL(G[7], 16) + BitUtil.Rotation.rotateL(G[6], 16) & 0xffffffffL);
            X[1] = (int) ((G[1] + BitUtil.Rotation.rotateL(G[0], 8) + G[7]) & 0xffffffffL);
            X[2] = (int) ((G[2] + BitUtil.Rotation.rotateL(G[1], 16) + BitUtil.Rotation.rotateL(G[0], 16)) & 0xffffffffL);
            X[3] = (int) ((G[3] + BitUtil.Rotation.rotateL(G[2], 8) + G[1]) & 0xffffffffL);
            X[4] = (int) ((G[4] + BitUtil.Rotation.rotateL(G[3], 16) + BitUtil.Rotation.rotateL(G[2], 16) & 0xffffffffL));
            X[5] = (int) ((G[5] + BitUtil.Rotation.rotateL(G[4], 8) + G[3]) & 0xffffffffL);
            X[6] = (int) ((G[6] + BitUtil.Rotation.rotateL(G[5], 16) + BitUtil.Rotation.rotateL(G[4], 16)) & 0xffffffffL);
            X[7] = (int) ((G[7] + BitUtil.Rotation.rotateL(G[6], 8) + G[5]) & 0xffffffffL);

        }

        private void counterUpdate() {

            for (int j = 0; j < 8; j++) {
                long temp = (C[j] & 0xFFFFFFFFl) + (A[j] & 0xFFFFFFFFl) + b;
                b = (byte) (temp >>> 32);
                C[j] = (int) (temp & 0xFFFFFFFFl);
            }

        }

        private byte[] next16() {
            nextState();
            short[] S = new short[8];
            S[7] = (short) (((X[0] & 0xffff) ^ ((X[5] >>> 0x10))) & 0xffff);
            S[6] = (short) ((((X[0] >>> 0x10) ^ (X[3] & 0xffff))) & 0xffff);
            S[5] = (short) (((X[2] & 0xffff) ^ (X[7] >>> 0x10)) & 0xffff);
            S[4] = (short) ((((X[2] >>> 0x10)) ^ (X[5] & 0xffff)) & 0xffff);
            S[3] = (short) (((X[4] & 0xffff) ^ (X[1] >>> 0x10)) & 0xffff);
            S[2] = (short) (((X[4] >>> 0x10) ^ (X[7] & 0xffff)) & 0xffff);
            S[1] = (short) (((X[6] & 0xffff) ^ (X[3] >>> 0x10)) & 0xffff);
            S[0] = (short) (((X[6] >>> 0x10) ^ (X[1] & 0xffff)) & 0xffff);
            return BitUtil.ByteArrays.shortArrayToByteArray(S);
        }

        private int g(int x, int y) {
            long f1 = ((x + y) & (0xffffffffL));
            f1 *= f1;
            int f1_L = (int) (f1 & 0xffffffffL);
            int f1_M = (int) ((f1 & 0xffffffff00000000L) >>> 32);
            return f1_M ^ f1_L;
        }


        @Override
        byte[] crypt(byte[] input) {
            int whenToStop = BitUtil.Extend.extendToSize(input.length, 16);
            byte[] keyStream = new byte[whenToStop];
            for (int i = 0; i < whenToStop; i += 16) {
                byte[] chunck = next16();
                System.arraycopy(chunck, 0, keyStream, i, 16);
            }
            byte[] keyStream_l = new byte[input.length];
            System.arraycopy(keyStream, 0, keyStream_l, 0, input.length);
            return BitUtil.Operation.XOR(input, keyStream_l);
        }

    }
}
