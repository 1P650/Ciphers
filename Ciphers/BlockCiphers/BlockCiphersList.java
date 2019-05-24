package Ciphers.BlockCiphers;

import java.util.HashMap;
import java.util.HashSet;

public interface BlockCiphersList {
    static BlockCipher GOST() {
        return new GOST89();
    }

    static BlockCipher TEA() {
        return new TEA();
    }


    static BlockCipher IDEA() {
        return new IDEA();
    }




}

