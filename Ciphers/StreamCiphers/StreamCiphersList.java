package Ciphers.StreamCiphers;

public interface StreamCiphersList {

    static StreamCipher HC256() {
        return new HC256();
    }
}
