package Ciphers.BlockCiphers;

import Ciphers.Basic.Cipher;
import Ciphers.Utils.BitUtil;

public class TEA implements Cipher {
    public static final byte ECB = 0;
    public static final byte CBC = 1;
    public static final byte OFB = 2;
    public static final byte CFB = 3;
    public static final byte CTR = 4;

    private static final byte KEY_SIZE = 16;
    private static final byte IV_SIZE = 8;

    private byte MODE_SELECTED = 0;
    private static TEA_algorithm rootTEA;

    private TEA() {
    }

    private TEA(byte mode) {
        setMode(mode);
    }

    private TEA(byte mode, byte[] key) {
        setMode(mode);
        setKey(key);
    }

    private TEA(byte mode, byte[] key, byte[] iv) {
        setMode(mode);
        setKey(key);
        setIV(iv);
    }

    public void setMode(byte mode) {
        if (mode < 0 || mode > 4) this.MODE_SELECTED = 0;
        else this.MODE_SELECTED = mode;
    }


    public void setIV(byte[] iv) {
        if (iv == null || iv.length != IV_SIZE) throw new TEA_exception(TEA_exception.IV_LEN);
        rootTEA.IV = iv;
    }


    public static TEA getInstance() {
        return new TEA();
    }

    public static TEA getInstance(byte mode) {
        return new TEA(mode);
    }

    public static TEA getInstance(byte mode, byte[] key) {
        return new TEA(mode, key);
    }

    public static TEA getInstance(byte mode, byte[] key, byte[] IV) {
        return new TEA(mode, key, IV);
    }


    @Override
    public void setKey(byte[] key) {
        if (key == null || key.length != KEY_SIZE) throw new TEA_exception(TEA_exception.KEY_LEN);
        rootTEA = new TEA_algorithm(key);

    }

    @Override
    public byte[] encrypt(byte[] plain) {
        if (plain == null || plain.length == 0) throw new TEA_exception(TEA_exception.DATA_NULL);
        switch (this.MODE_SELECTED) {
            case TEA.CBC:
                return rootTEA.encryptInCBC(plain);
            case TEA.OFB:
                return rootTEA.encryptInOFB(plain);
            case TEA.CFB:
                return rootTEA.encryptInCFB(plain);
            case TEA.CTR:
                return rootTEA.encryptInCTR(plain);
            default:
                return rootTEA.encryptInECB(plain);
        }

    }

    @Override
    public byte[] decrypt(byte[] ciph) {
        if (ciph == null || ciph.length == 0) throw new TEA_exception(TEA_exception.DATA_NULL);
        switch (this.MODE_SELECTED) {
            case TEA.CBC:
                return rootTEA.decryptInCBC(ciph);
            case TEA.OFB:
                return rootTEA.decryptInOFB(ciph);
            case TEA.CFB:
                return rootTEA.decryptInCFB(ciph);
            case TEA.CTR:
                return rootTEA.decryptInCTR(ciph);
            default:
                return rootTEA.decryptInECB(ciph);
        }
    }

    @Override
    public void reset() {
        this.MODE_SELECTED = 0;
        rootTEA = new TEA_algorithm();

    }


    private class TEA_algorithm {
        private byte[] IV = null;
        private int DELTA_E = 0x9e3779b9;
        private int DELTA_D = 0xc6ef3720;
        private int K0, K1, K2, K3 = 0;

        TEA_algorithm() {
        }

        TEA_algorithm(byte[] key) {
            byte[] K0_B = new byte[4];
            byte[] K1_B = new byte[4];
            byte[] K2_B = new byte[4];
            byte[] K3_B = new byte[4];

            System.arraycopy(key, 0, K0_B, 0, 4);
            System.arraycopy(key, 4, K1_B, 0, 4);
            System.arraycopy(key, 8, K2_B, 0, 4);
            System.arraycopy(key, 12, K3_B, 0, 4);

            this.K0 = BitUtil.ByteArrays.byteArrayToInt(K0_B);
            this.K1 = BitUtil.ByteArrays.byteArrayToInt(K1_B);
            this.K2 = BitUtil.ByteArrays.byteArrayToInt(K2_B);
            this.K3 = BitUtil.ByteArrays.byteArrayToInt(K3_B);
            K0_B = null;
            K1_B = null;
            K2_B = null;
            K3_B = null;
        }


        byte[] encryptInECB(byte[] input) {
            if (input.length % 8 != 0) throw new TEA_exception(TEA_exception.DATA_LEN);
            int[] plain_32 = BitUtil.ByteArrays.byteArrayToIntArray(input);
            for (int k = 0; k < plain_32.length - 1; k += 2) {

                int L = plain_32[k];
                int R = plain_32[k + 1];
                int delta_e = 0;
                for (int i = 0; i < 32; i++) {
                    delta_e += DELTA_E;
                    L += ((R << 4) + K0) ^ (R + delta_e) ^ ((R >> 5) + K1);
                    R += ((L << 4) + K2) ^ (L + delta_e) ^ ((L >> 5) + K3);
                }
                plain_32[k] = L;
                plain_32[k + 1] = R;
            }
            return BitUtil.ByteArrays.intArrayToByteArray(plain_32);

        }

        byte[] decryptInECB(byte[] input) {
            int[] plain_32 = BitUtil.ByteArrays.byteArrayToIntArray(input);

            for (int k = 0; k < plain_32.length - 1; k += 2) {
                int L = plain_32[k];
                int R = plain_32[k + 1];
                int delta_d = DELTA_D;
                for (int i = 0; i < 32; i++) {
                    R -= ((L << 4) + K2) ^ (L + delta_d) ^ ((L >> 5) + K3);
                    L -= ((R << 4) + K0) ^ (R + delta_d) ^ ((R >> 5) + K1);
                    delta_d -= DELTA_E;
                }
                plain_32[k] = L;
                plain_32[k + 1] = R;
            }


            return BitUtil.ByteArrays.intArrayToByteArray(plain_32);

        }

        byte[] encryptInCBC(byte[] input) {
            if (this.IV == null) throw new TEA_exception(TEA_exception.IV_NULL);
            byte last_len = (byte) (input.length % 8 == 0 ? 0 : BitUtil.Extend.extendToSize(input.length, 8) - input.length);
            byte[] input_extended = new byte[input.length % 8 == 0 ? input.length + 8 : BitUtil.Extend.extendToSize(input.length, 8)];
            System.arraycopy(input, 0, input_extended, 0, input.length);
            for (int i = input.length; i < input_extended.length; i++) input_extended[i] = last_len;
            byte[] STATE = this.IV.clone();
            byte[] encrypted = new byte[input_extended.length];

            for (int i = 0; i < input_extended.length; i += 8) {
                byte[] chunck = new byte[8];
                System.arraycopy(input_extended, i, chunck, 0, 8);
                chunck = encryptInECB(BitUtil.Operation.Xor(STATE, chunck));
                STATE = chunck.clone();
                System.arraycopy(chunck, 0, encrypted, i, 8);
            }


            return encrypted;


        }

        byte[] decryptInCBC(byte[] input) {
            if (this.IV == null) throw new TEA_exception(TEA_exception.IV_NULL);
            byte[] STATE = this.IV.clone();
            byte[] decrypted_extended = new byte[input.length];
            for (int i = 0; i <= input.length - 8; i += 8) {
                byte[] chunck = new byte[8];
                System.arraycopy(input, i, chunck, 0, chunck.length);
                byte[] STATE_m = chunck.clone();
                chunck = BitUtil.Operation.Xor(STATE, decryptInECB(chunck));
                STATE = STATE_m;
                System.arraycopy(chunck, 0, decrypted_extended, i, 8);
            }

            byte len = decrypted_extended[decrypted_extended.length - 1];
            if (len == 0) len = 8;
            byte[] decrypted = new byte[decrypted_extended.length - len];
            System.arraycopy(decrypted_extended, 0, decrypted, 0, decrypted.length);
            return decrypted;
        }

        byte[] encryptInOFB(byte[] input) {
            if (this.IV == null) throw new TEA_exception(TEA_exception.IV_NULL);
            byte[] gamma = new byte[BitUtil.Extend.extendToSize(input.length, 8)];
            byte[] STATE = this.IV.clone();
            for (int i = 0; i < gamma.length; i += 8) {
                STATE = encryptInECB(STATE);
                System.arraycopy(STATE, 0, gamma, i, 8);
            }

            return BitUtil.Operation.Xor(input, gamma);

        }

        byte[] decryptInOFB(byte[] input) {
            if (this.IV == null) throw new TEA_exception(TEA_exception.IV_NULL);
            byte[] gamma = new byte[BitUtil.Extend.extendToSize(input.length, 8)];
            byte[] STATE = this.IV.clone();
            for (int i = 0; i < gamma.length; i += 8) {
                STATE = encryptInECB(STATE);
                System.arraycopy(STATE, 0, gamma, i, 8);
            }

            return BitUtil.Operation.Xor(input, gamma);


        }

        byte[] encryptInCFB(byte[] input) {
            if (this.IV == null) throw new TEA_exception(TEA_exception.IV_NULL);
            int len = BitUtil.Extend.extendToSize(input.length, 8);
            byte[] extended = new byte[len];

            System.arraycopy(input, 0, extended, 0, input.length);
            byte[] STATE = this.IV.clone();

            for (int i = 0; i < extended.length; i += 8) {
                STATE = encryptInECB(STATE);
                byte[] chunck = new byte[8];
                System.arraycopy(extended, i, chunck, 0, 8);
                chunck = BitUtil.Operation.Xor(chunck, STATE);
                System.arraycopy(chunck, 0, extended, i, 8);
                STATE = chunck;

            }

            byte[] encrypted = new byte[input.length];

            System.arraycopy(extended, 0, encrypted, 0, encrypted.length);
            return encrypted;
        }

        byte[] decryptInCFB(byte[] input) {
            if (this.IV == null) throw new TEA_exception(TEA_exception.IV_NULL);
            int len = BitUtil.Extend.extendToSize(input.length, 8);
            byte[] extended = new byte[len];
            System.arraycopy(input, 0, extended, 0, input.length);

            byte[] decrypted = new byte[input.length];

            byte[] STATE = this.IV.clone();
            for (int i = 0; i < input.length; i += 8) {
                STATE = encryptInECB(STATE);
                byte[] chunck = new byte[8];
                System.arraycopy(extended, i, chunck, 0, 8);
                System.arraycopy(BitUtil.Operation.Xor(chunck.clone(), STATE), 0, extended, i, 8);
                STATE = chunck;
            }
            System.arraycopy(extended, 0, decrypted, 0, decrypted.length);
            return decrypted;
        }

        byte[] encryptInCTR(byte[] input) {
            if (this.IV == null) throw new TEA_exception(TEA_exception.IV_NULL);
            byte[] gamma = new byte[BitUtil.Extend.extendToSize(input.length, 8)];
            byte[] CTR = this.IV.clone();
            for (int i = 0; i < gamma.length; i += 8) {
                CTR = encryptInECB(BitUtil.ByteArrays.longToByteArray(BitUtil.ByteArrays.byteArrayToLong(CTR) + 1));
                System.arraycopy(CTR, 0, gamma, i, 8);
            }

            return BitUtil.Operation.Xor(input, gamma);
        }

        byte[] decryptInCTR(byte[] input) {
            if (this.IV == null) throw new TEA_exception(TEA_exception.IV_NULL);
            byte[] gamma = new byte[BitUtil.Extend.extendToSize(input.length, 8)];
            byte[] CTR = this.IV.clone();
            for (int i = 0; i < gamma.length; i += 8) {
                CTR = encryptInECB(BitUtil.ByteArrays.longToByteArray(BitUtil.ByteArrays.byteArrayToLong(CTR) + 1));
                System.arraycopy(CTR, 0, gamma, i, 8);
            }

            return BitUtil.Operation.Xor(input, gamma);
        }


    }


    private class TEA_exception extends RuntimeException {
        final static String KEY_LEN = "Key length must be 128 bit (16 bytes)!";
        final static String IV_LEN = "IV length must be 64 bit (8 bytes)!";
        final static String DATA_LEN = "Data length must be multiple of 8!";
        final static String DATA_NULL = "Data length must be >0!";
        final static String IV_NULL = "Initialization Vector is not set! Set it with TEA.setIV(byte[] IV)";

        TEA_exception() {
            super();
        }

        TEA_exception(String e) {
            super(e);
        }
    }
}
