package Ciphers.BlockCiphers;


public interface BlockCiphersList {


    static BlockCipher IDEA(){ return new IDEA();}
    static BlockCipher GOST(){ return new GOST89();}
    static BlockCipher TEA(){ return new TEA();}
    static BlockCipher CAST5(){return new CAST5();}
    









}

