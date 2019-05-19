package Ciphers.BlockCiphers;

import Ciphers.Basic.HashFunction;
import Ciphers.Basic.PRN_generator;
import Ciphers.Utils.BitUtil;
import Ciphers.HashFunctions.SHA2.SHA256;
import Ciphers.HashFunctions.SHA2.SHA512;
import Ciphers.RND_generators.ISAAC;


public class Aardvark implements Ciphers.Basic.Cipher {
    private byte[] K;
    private HashFunction hashFunction;
    private PRN_generator generator;
    private Aardvark(){
        this.hashFunction = new SHA512();
        this.generator = new ISAAC();
    }
    private Aardvark(HashFunction function, PRN_generator gen){
        this.hashFunction = function;
        this.generator = gen;
    }

    public static Aardvark getInstance(){
        return new Aardvark();
    }
    public static Aardvark getInstance(HashFunction function, PRN_generator gen){
        return new Aardvark(function,gen);
    }

    @Override
    public void setKey(byte[] K) {
        this.K = K;
    }

    public void setHashFunction(HashFunction hashFunction){this.hashFunction = hashFunction;}
    public void setGenerator(PRN_generator generator){this.generator = generator;}

    @Override
    public byte[] encrypt(byte[] P) {
        byte[] C1 = H(P);
        byte[] C2 = H(C1, K);
        byte[] C3 = S(C2, P.length);
        byte[] C4 = BitUtil.Operation.Xor(P,C3);
        byte[] C = new byte[C4.length + C1.length];
        System.arraycopy(C1, 0, C,0,C1.length);
        System.arraycopy(C4, 0,C,C1.length,C4.length);
        return C;
    }



    @Override
    public byte[] decrypt(byte[] C) {
        int len = hashFunction.getLength();
        byte[] C1 = new byte[len];
        byte[] C0 = new byte[C.length - len];
        System.arraycopy(C,0,C1,0,len);
        System.arraycopy(C, C1.length, C0, 0, C.length-len);
        byte[] C2 = H(C1, K);
        byte[] C3 = S(C2, C0.length);
        byte[] P = BitUtil.Operation.Xor(C0,C3);
        return P;
    }


    @Override
    public void reset() {
        this.setKey(new byte[0]);
        this.setHashFunction(new SHA256());
        this.setGenerator(new ISAAC());
    }

    private  byte[] S(byte[] seed, int S_len){
        generator.setSeed(seed);
        byte[] bytes = new byte[S_len];
        bytes = generator.nextBytes(bytes);
        generator.reset();
        return bytes;
    }

    private  byte[] H(byte[] input){
        return hashFunction.process(input);

    }
    private  byte[] H(byte[] input, byte[] K){
        byte[] a = new byte[input.length + K.length*2];
        System.arraycopy(K,0,a,0,K.length);
        System.arraycopy(input,0,a,K.length,input.length);
        System.arraycopy(K,0,a,input.length + K.length,K.length);
        return hashFunction.process(a);
    }

}
