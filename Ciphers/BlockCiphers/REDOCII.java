package Ciphers.BlockCiphers;

class REDOCII extends BlockCipher {
    private REDOCII_algorithm REDOC_A;
    private final int[] KEY_SIZES = new int[]{8,2240};
    REDOCII(){
        REDOC_A = new REDOCII_algorithm();
        super.algorithm = REDOC_A;
        super.KeySize = 2240;
        super.IV_Size = 10;
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

    private class REDOCII_algorithm extends BlockCipher.BlockCipherAlgorithm{
        REDOCII_algorithm(){
            super.blocksize = 10;
        }

        REDOCII_algorithm(byte[] key){
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
