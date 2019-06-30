package Ciphers.BlockCiphers;

class REDOCII extends BlockCipher {
    private REDOCII_algorithm REDOC_A;
    private final int[] KEY_SIZES = new int[]{8, 2240};


    REDOCII() {
        REDOC_A = new REDOCII_algorithm();
        super.algorithm = REDOC_A;
        super.KeySize = 2240;
        super.IV_Size = 10;
        super.PossibleKeySizes = KEY_SIZES;
    }

    @Override
    public void setKey(byte[] key) {
        if (key == null || (key.length < KEY_SIZES[0] || key.length > KEY_SIZES[1]))
            throw new BlockCipherException(BlockCipherException.KEY_LEN_MANY, "from 80 up to 17 920 (%8 = 0)", "from 8 up to 2240");
        byte[] IV_save = REDOC_A == null ? null : REDOC_A.IV;
        REDOC_A = new REDOCII_algorithm(key);
        REDOC_A.IV = IV_save;
        super.algorithm = REDOC_A;
    }

    private class REDOCII_algorithm extends BlockCipher.BlockCipherAlgorithm {
        private int ROUNDS = 10;
        private final byte[][] SUBSTITION_TABLE = new byte[16][128];
        private final byte[][] PERMUTATION_TABLE = new byte[128][10];
        private final byte[][][][] ENCLAVE_TABLE = new byte[32][4][3][5];
        private byte[][] KEY_TABLE = new byte[128][10];
        private byte[][] MASK_TABLE = new byte[9][10];

        private final byte[][] SUBSTITION_TABLE_INVERTED = new byte[16][128];
        private final byte[][] PERMUTATION_TABLE_INVERTED = new byte[128][10];
        private final byte[][][][] ENCLAVE_TABLE_INVERTED = new byte[32][4][3][5];
        REDOCII_algorithm() {
            super.blocksize = 10;
        }

        REDOCII_algorithm(byte[] key) {
            super.blocksize = 10;

        }

        @Override
        byte[] encryptInECB(byte[] input) {
            return new byte[0];
        }

        @Override
        byte[] decryptInECB(byte[] input) {
            return new byte[0];
        }
    }
}
