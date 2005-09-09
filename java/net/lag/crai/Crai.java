package net.lag.crai;

import java.math.BigInteger;


/**
 * Crypto abstraction interface.
 * 
 * <p>Not every platform has JCE, so this interface allows you to wrap your
 * native crypto libraries so that they can be used by jaramiko.
 *
 * @author robey
 */
public interface Crai
{
    public CraiRandom getPRNG ();
    
    public CraiPrivateKey makePrivateRSAKey (BigInteger n, BigInteger d);
    public CraiPrivateKey makePrivateDSAKey (BigInteger x, BigInteger p, BigInteger q, BigInteger g);
    public CraiPublicKey makePublicRSAKey (BigInteger n, BigInteger e);
    public CraiPublicKey makePublicDSAKey (BigInteger y, BigInteger p, BigInteger q, BigInteger g);
}
