/*
 * Created on May 8, 2005
 */

package net.lag.paramiko;

/**
 * @author robey
 */
public interface LogSink
{
    public void error (String text);
    public void warning (String text);
    public void notice (String text);
    public void debug (String text);
    public void dump (String text, byte[] data, int offset, int length);
}
