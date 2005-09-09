package net.lag.crai;

public interface CraiPublicKey
{
    public boolean verify(byte[] data, int off, int len, byte[] signature) throws CraiException;
}
