package net.lag.crai;

public interface CraiPrivateKey
{
    public byte[] sign(byte[] data, int off, int len) throws CraiException;
}
