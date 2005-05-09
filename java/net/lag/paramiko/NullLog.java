/*
 * Created on May 8, 2005
 */

package net.lag.paramiko;

/**
 * Throw away all log messages.
 * 
 * @author robey
 */
public class NullLog
    implements LogSink
{
    public void
    error (String text)
    {
        // pass
    }

    public void
    warning (String text)
    {
        // pass
    }

    public void
    notice (String text)
    {
        // pass
    }

    public void
    debug (String text)
    {
        // pass
    }

    public void
    dump (String text, byte[] data, int offset, int length)
    {
        // pass
    }
}
