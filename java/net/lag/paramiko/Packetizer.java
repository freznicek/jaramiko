/*
 * Copyright (C) 2005 Robey Pointer <robey@lag.net>
 *
 * This file is part of paramiko.
 *
 * Paramiko is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Paramiko; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 *
 *
 * Created on May 7, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;


/**
 * Stream for reading and writing SSH2 {@link Message} objects.  Encryption and
 * re-keying are handled at this layer.
 * 
 * @author robey
 */
/* package */ class Packetizer
{
    public
    Packetizer (InputStream in, OutputStream out, SecureRandom random)
        throws IOException
    {
        mInStream = in;
        mOutStream = out;
        mRandom = random;
        mClosed = false;
        mLog = new NullLog();
        mDumpPackets = false;
        
        mWriteLock = new Object();
    }
    
    public void
    setLog (LogSink log)
    {
        mLog = log;
    }

    public void
    write (Message msg)
        throws IOException
    {
        msg.packetize(mRandom, mBlockSizeOut);
        byte[] packet = msg.toByteArray();
        int length = msg.getPosition();
        mLog.debug("Write packet <" + MessageType.getDescription(packet[5]) + ">, length " + length);
        if (mDumpPackets) {
            mLog.dump("OUT", packet, 0, length);
        }
        
        synchronized (mWriteLock) {
            if (mBlockEngineOut != null) {
                try {
                    mBlockEngineOut.update(packet, 0, length, packet, 0);
                } catch (ShortBufferException x) {
                    throw new IOException("encipher error: " + x);
                }

                new Message(mMacBufferOut).putInt(mSequenceNumberOut);
                mMacEngineOut.update(mMacBufferOut, 0, 4);
                mMacEngineOut.update(packet, 0, length);
                try {
                    mMacEngineOut.doFinal(mMacBufferOut, 0);
                } catch (ShortBufferException x) {
                    throw new IOException("mac error: " + x);
                }
            }
            
            mSequenceNumberOut++;
            write(packet, 0, length);
            if (mBlockEngineOut != null) {
                write(mMacBufferOut, 0, mMacSizeOut);
            }
            
            mSentBytes += length;
            mSentPackets++;
            if (((mSentPackets >= REKEY_PACKETS) || (mSentBytes >= REKEY_BYTES)) && ! mNeedRekey) {
                // only ask once for rekeying
                mLog.debug("Rekeying (hit " + mSentPackets + " packets, " + mSentBytes + " bytes sent)");
                mReceivedPacketsOverflow = 0;
                triggerRekey();
            }
        }
    }
    
    // do not return until the entire buffer is read, or EOF
    private int
    read (byte[] buffer, int offset, int length)
        throws IOException
    {
        int total = 0;
        while (true) {
            try {
                int n = mInStream.read(buffer, offset + total, length - total);
                if (n > 0) {
                    total += n;
                }
                if (n < 0) {
                    // EOF: no partial results
                    return n;
                }
            } catch (SocketTimeoutException x) {
                // pass
            }

            synchronized (this) {
                if (mClosed) {
                    return -1;
                }
            }
            checkKeepAlive();
        }
    }
    
    private void
    write (byte[] buffer, int offset, int length)
        throws IOException
    {
        // setSoTimeout() does not affect writes in java
        mOutStream.write(buffer, offset, length);
    }
    
    // really inefficient, but only used for 1 line at the start of the session
    private String
    readline ()
        throws IOException
    {
        StringBuffer line = new StringBuffer();
        
        while (true) {
            int c = mInStream.read();
            if (c < 0) {
                return null;
            }
            // only ASCII is allowed here, so this is ok; calm down. :)
            if ((char)c == '\n') {
                if ((line.length() > 0) && (line.charAt(line.length() - 1) == '\r')) {
                    line.setLength(line.length() - 1);
                }
                return line.toString();
            }
            line.append((char)c);
        }
    }
    
    private void
    checkKeepAlive ()
    {
        // pass - FIXME
    }
    
    private synchronized void
    triggerRekey ()
    {
        mNeedRekey = true;
    }
    
    
    private final static int READ_TIMEOUT = 1000;
    private final static int WRITE_TIMEOUT = 1000;
    
    /* READ the secsh RFC's before raising these values.  if anything, they
     * should probably be lower.
     */
    private final static int REKEY_PACKETS = 0x40000000;
    private final static int REKEY_BYTES = 0x40000000;      // 1GB

    private InputStream mInStream;
    private OutputStream mOutStream;
    private SecureRandom mRandom;
    private LogSink mLog;
    private boolean mClosed;
    private boolean mDumpPackets;
    private boolean mNeedRekey;
    
    private Object mWriteLock;
    
    private int mBlockSizeOut = 8;
    private int mBlockSizeIn = 8;
    private Cipher mBlockEngineOut;
    private Cipher mBlockEngineIn;
    private Mac mMacEngineOut;
    private Mac mMacEngineIn;
    private byte[] mMacBufferOut;
    private byte[] mMacBufferIn;
    private int mMacSizeOut;
    private int mMacSizeIn;
    private int mSequenceNumberOut;
    private int mSequenceNumberIn;
    
    private long mSentBytes;
    private long mSentPackets;
    private int mReceivedPacketsOverflow;
}
