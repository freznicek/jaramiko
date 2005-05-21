/*
 * Created on May 21, 2005
 */

package net.lag.paramiko;

/**
 * Exception raised when a password is needed to unlock a private key file.
 * 
 * @author robey
 */
public class PasswordRequiredException
    extends SSHException
{
    public
    PasswordRequiredException (String description)
    {
        super(description);
    }


    private static final long serialVersionUID = 0;
}
