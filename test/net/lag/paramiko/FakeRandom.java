/*
 * Created on May 23, 2005
 */

package net.lag.paramiko;

import java.security.SecureRandom;

/**
 * @author robey
 */
public class FakeRandom
    extends SecureRandom
{
    public void
    nextBytes (byte[] b)
    {
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte)0xcc;
        }
    }
    
    private static final long serialVersionUID = 0;
}
