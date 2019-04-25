package BlockCiphers;

import HashFunctions.SHA512;
import java.security.SecureRandom;


public class Aardvark implements Basic.Cipher {
    private byte[] K;
    private static HashFunctions.SHA512 SHA512;
    private Aardvark(){
        SHA512 = new SHA512();
    }

    public static Aardvark getInstance(){
        return new Aardvark();
    }

    @Override
    public void setKey(byte[] K) {
        this.K = K;
    }

    @Override
    public byte[] encrypt(byte[] P) {
        byte[] C1 = H(P);
        byte[] C2 = H(C1, K);
        byte[] C3 = S(C2, P.length);
        byte[] C4 = xor(P,C3);
        byte[] C = new byte[C4.length + C1.length];
        System.arraycopy(C1, 0, C,0,C1.length);
        System.arraycopy(C4, 0,C,C1.length,C4.length);
        return C;
    }



    @Override
    public byte[] decrypt(byte[] C) {
        byte[] C1 = new byte[64];
        byte[] C0 = new byte[C.length - 64];
        System.arraycopy(C,0,C1,0,64);
        System.arraycopy(C, C1.length, C0, 0, C.length-64);
        byte[] C2 = H(C1, K);
        byte[] C3 = S(C2, C0.length);
        byte[] P = xor(C0,C3);
        return P;
    }
    private static byte[] xor(byte[] a, byte[] b){
        for (int i = 0; i < a.length; i++) {
            a[i]^=b[i];
        }
        return a;
    }

    @Override
    public void reset() {
        this.setKey(new byte[0]);
    }

    private static byte[] S(byte[] seed, int S_len){
        SecureRandom random = new SecureRandom();
        random.setSeed(seed);
        byte[] bytes = new byte[S_len];
        random.nextBytes(bytes);
        return bytes;
    }

    private static byte[] H(byte[] input){
        return SHA512.process(input);

    }
    private static byte[] H(byte[] input, byte[] K){
        byte[] a = new byte[input.length + K.length*2];
        System.arraycopy(K,0,a,0,K.length);
        System.arraycopy(input,0,a,K.length,input.length);
        System.arraycopy(K,0,a,input.length + K.length,K.length);
        return SHA512.process(a);
    }

}
