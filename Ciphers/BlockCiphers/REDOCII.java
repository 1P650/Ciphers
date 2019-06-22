package Ciphers.BlockCiphers;

public class REDOCII extends BlockCipher {
    @Override
    public void setKey(byte[] key) {

    }

    private class REDOCII_algorithm extends BlockCipher.BlockCipherAlgorithm{

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
