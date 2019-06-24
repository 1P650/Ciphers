package Ciphers.BlockCiphers;

class Threefish extends BlockCipher {
    @Override
    public void setKey(byte[] key) {

    }

    private class Threefish_algorithm extends BlockCipherAlgorithm{

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
