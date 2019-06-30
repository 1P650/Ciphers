package Ciphers.StreamCiphers;

public interface StreamCiphersList {

    static StreamCipher HC256() {
        return new HC256();
    }

    static StreamCipher Rabbit() {
        return new Rabbit();
    }
    static StreamCipher Trivium() {
        return new Trivium();
    }
}
