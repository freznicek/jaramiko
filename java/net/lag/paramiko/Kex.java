/*
 * Created on May 13, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.security.SecureRandom;

/**
 * Interface for implementing a key-exchange algorithm.
 * 
 * @author robey
 */
/* package */ interface Kex
    extends MessageHandler
{
    public String getName ();
    public void startKex (TransportInterface t, SecureRandom r) throws IOException;
}
