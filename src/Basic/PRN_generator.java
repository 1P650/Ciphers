package Basic;

public interface PRN_generator {
    void setSeed(byte[] seed);
    byte[] nextBytes(byte[] in);
    void reset();

}
