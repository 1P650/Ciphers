package Basic;

public interface HashFunction {

     byte[] process(byte[] input);
     void reset();
}
