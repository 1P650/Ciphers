package Ciphers.BlockCiphers;

public class Cobra extends BlockCipher {
    @Override
    public void setKey(byte[] key) {

    }

    private class Cobra_algorithm extends BlockCipher.BlockCipherAlgorithm{

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
