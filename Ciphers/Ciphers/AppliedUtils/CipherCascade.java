package Ciphers.AppliedUtils;

import Ciphers.Basic.Cipher;


public class CipherCascade {
    private java.util.ArrayList<Cipher> ciphers;

    public CipherCascade(java.util.ArrayList<Cipher> cipher_list) {
        this.ciphers = cipher_list;

    }

    public CipherCascade() {
        this.ciphers = new java.util.ArrayList<>();
    }

    public byte[] encryptByCascade(byte[] input) {
        byte[] encrypted = input.clone();
        for (java.util.Iterator<Cipher> I_C = this.ciphers.iterator(); I_C.hasNext(); ) {
            Cipher currentState = I_C.next();
            encrypted = currentState.encrypt(encrypted);

        }
        return encrypted;
    }

    public byte[] decryptByCascade(byte[] input) {
        byte[] decrypted = input.clone();
        java.util.ArrayList<Cipher> reversed = (java.util.ArrayList<Cipher>) this.ciphers.clone();
        java.util.Collections.reverse(reversed);
        for (java.util.Iterator<Cipher> I_C = reversed.iterator(); I_C.hasNext(); ) {
            Cipher currentState = I_C.next();
            decrypted = currentState.decrypt(decrypted);

        }
        return decrypted;
    }

    public void add(Cipher input) {
        this.ciphers.add(input);
    }

    public Cipher get(int index) {
        try {
            return this.ciphers.get(index);
        } catch (IndexOutOfBoundsException e) {
            return null;
        }

    }

    public void addTo(int index, Cipher cipher) {
        this.ciphers.add(index, cipher);
    }

    public void remove(int index) {
        this.ciphers.remove(index);
    }

    public void removeLast() {
        this.ciphers.remove(this.ciphers.size() - 1);
    }

    public void removeFirst() {
        this.ciphers.remove(0);
    }

    public void clear() {
        this.ciphers.clear();
    }


    public void printState() {
        java.io.PrintStream stream = new java.io.PrintStream(System.out);
        for (java.util.Iterator<Cipher> I_C = this.ciphers.iterator(); I_C.hasNext(); ) {
            stream.println(I_C.next().toString());
        }
        stream.print("\n");

    }
}




