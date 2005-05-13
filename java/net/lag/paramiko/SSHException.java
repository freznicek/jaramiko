/*
 * Created on May 12, 2005
 */

package net.lag.paramiko;

import java.io.IOException;

/**
 * An exception raised by failures in the SSH2 protocol.
 * 
 * @author robey
 */
public class SSHException
    extends IOException
{
    public
    SSHException (String description)
    {
        super(description);
    }
    
    
    private static final long serialVersionUID = 0;
}
