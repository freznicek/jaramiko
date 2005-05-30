/*
 * Created on May 10, 2005
 */
package net.lag.paramiko;

/**
 * @author robey
 */
public class ConsoleLog
    implements LogSink
{
    public void
    error (String text)
    {
        System.err.println("ERR: " + text);
    }

    public void
    warning (String text)
    {
        System.err.println("WRN: " + text);
    }

    public void
    notice (String text)
    {
        System.err.println("NTC: " + text);
    }

    public void
    debug (String text)
    {
        System.err.println("DBG: " + text);
    }

    public void
    dump (String text, byte[] data, int offset, int length)
    {
        for (int i = 0; i < length; i += 16) {
            System.err.println("DMP: " + text + ": " + dumpHex(data, offset + i, length - i));
        }
    }
    
    private String
    dumpHex (byte[] data, int offset, int length)
    {
        StringBuffer hex = new StringBuffer();
        StringBuffer ascii = new StringBuffer();
        
        for (int i = 0; i < 16; i++) {
            if (i >= length) {
                hex.append("   ");
                ascii.append(' ');
            } else {
                byte b = data[offset + i];
                String x = Integer.toHexString((int)b & 0xff).toUpperCase();
                if (x.length() < 2) {
                    hex.append('0');
                }
                hex.append(x);
                hex.append(' ');

                if ((b > 32) && (b < 127)) {
                    ascii.append((char)b);
                } else {
                    ascii.append('.');
                }
            }
        }
        
        return hex.toString() + "   " + ascii.toString();
    }

}
