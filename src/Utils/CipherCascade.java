package Utils;

import Basic.Cipher;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

public class CipherCascade<C extends Cipher> {
    private ArrayList<Cipher> ciphers;

    public CipherCascade(ArrayList<Cipher> cipher_list) {
        this.ciphers = cipher_list;

    }

    public CipherCascade() {
        this.ciphers = new ArrayList<>();
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

    public byte[] encryptByCascade(byte[] input) {
        byte[] encrypted = input.clone();
        for (Iterator<Cipher> I_C = this.ciphers.iterator(); I_C.hasNext(); ) {
            Cipher currentState = I_C.next();
            encrypted = currentState.encrypt(encrypted);

        }
        return encrypted;
    }

    public byte[] decryptByCascade(byte[] input) {
        byte[] decrypted = input.clone();
        ArrayList<Cipher> reversed = (ArrayList<Cipher>) this.ciphers.clone();
        Collections.reverse(reversed);
        for (Iterator<Cipher> I_C = reversed.iterator(); I_C.hasNext(); ) {
            Cipher currentState = I_C.next();
            decrypted = currentState.decrypt(decrypted);

        }
        return decrypted;
    }

    public void printState() {
        for (Iterator<Cipher> I_C = this.ciphers.iterator(); I_C.hasNext(); ) {
            System.out.println(I_C.next().toString());
        }
        System.out.println();

    }
}




