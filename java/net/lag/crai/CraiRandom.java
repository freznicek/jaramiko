package net.lag.crai;

/**
 * Interface for generating crypto-quality pseudo-random numbers.
 * 
 * @author robey
 */
public interface CraiRandom
{
    /**
     * Fill a byte buffer with pseudo-random bytes.
     * 
     * @param b the buffer to fill
     */
    public void getBytes (byte[] b);
}
