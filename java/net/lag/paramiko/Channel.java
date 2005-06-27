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
 * Created on Jun 10, 2005
 */

package net.lag.paramiko;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;

/*
 * locking order:  mInBufferLock, mInStderrBufferLock, mLock
 * 
 * mInBufferLock protects: mInBuffer, mInBufferLen
 * mInStderrBufferLock protects: mInStderrBuffer, mInStderrBufferLen
 * mOutBufferLock protects: mOutWindowSize, outbound packets
 * mLock protects: mActive, mClosed, mEOFReceived, mEOFSent, mCombineStderr
 */

/**
 * @author robey
 */
public class Channel
    implements MessageHandler
{
    /* package */
    Channel (int chanid)
    {
        mChanID = chanid;
        mActive = false;
        mClosed = false;
        mEOFReceived = false;
        mEOFSent = false;
        mLock = new Object();
        mEvent = new Event();
        // ...
        
        mInBuffer = new byte[64];
        mInBufferLen = 0;
        mInBufferLock = new Object();
        mInStderrBuffer = new byte[64];
        mInStderrBufferLen = 0;
        mInStderrBufferLock = new Object();
        mOutBufferLock = new Object();
        
        mStatusEvent = new Event();
        mTimeout = 0;   // infinite, in java-speek
    }

    
    private class ChannelInputStream
        extends InputStream
    {
        public int
        available ()
        {
            synchronized (mInBufferLock) {
                return mInBufferLen;
            }
        }
        
        public int
        read ()
            throws IOException
        {
            byte[] b = new byte[1];
            if (read(b, 0, 1) < 1) {
                return -1;
            }
            return (int) b[0] & 0xff;
        }
        
        public int
        read (byte[] buf, int off, int len)
            throws IOException
        {
            synchronized (mInBufferLock) {
                if (mInBufferLen == 0) {
                    int timeout = mTimeout;
                    while (mInBufferLen == 0) {
                        synchronized (mLock) {
                            if (mClosed || mEOFReceived) {
                                break;
                            }
                        }
                        
                        long then = System.currentTimeMillis();
                        try {
                            mInBufferLock.wait(timeout);
                        } catch (InterruptedException x) { }
                        if (mTimeout > 0) {
                            timeout -= System.currentTimeMillis() - then;
                            if (timeout <= 0) {
                                throw new SocketTimeoutException();
                            }
                        }
                    }
                    
                    synchronized (mLock) {
                        if (mEOFReceived) {
                            return 0;
                        }
                        if (mClosed) {
                            throw new IOException("Stream closed.");
                        }
                    }
                }
                
                // something in the buffer
                if (mInBufferLen <= len) {
                    System.arraycopy(mInBuffer, 0, buf, off, mInBufferLen);
                    len = mInBufferLen;
                    mInBufferLen = 0;
                    checkAddWindow(len);
                    return len;
                } else {
                    System.arraycopy(mInBuffer, 0, buf, off, len);
                    System.arraycopy(mInBuffer, len, mInBuffer, 0, mInBufferLen - len);
                    mInBufferLen -= len;
                    checkAddWindow(len);
                    return len;
                }
            }
        }
    
        public void
        close ()
        {
            Channel.this.close();
        }
    }
    
    private class ChannelStderrInputStream
        extends InputStream
    {
        public int
        available ()
        {
            synchronized (mInStderrBufferLock) {
                return mInStderrBufferLen;
            }
        }
    
        public int
        read ()
            throws IOException
        {
            byte[] b = new byte[1];
            if (read(b, 0, 1) < 1) {
                return -1;
            }
            return (int) b[0] & 0xff;
        }
    
        public int
        read (byte[] buf, int off, int len)
            throws IOException
        {
            synchronized (mInStderrBufferLock) {
                if (mInStderrBufferLen == 0) {
                    int timeout = mTimeout;
                    while (mInStderrBufferLen == 0) {
                        synchronized (mLock) {
                            if (mClosed || mEOFReceived) {
                                break;
                            }
                        }

                        long then = System.currentTimeMillis();
                        try {
                            mInStderrBufferLock.wait(timeout);
                        } catch (InterruptedException x) { }
                        if (mTimeout > 0) {
                            timeout -= System.currentTimeMillis() - then;
                            if (timeout <= 0) {
                                throw new SocketTimeoutException();
                            }
                        }
                    }
                    
                    synchronized (mLock) {
                        if (mEOFReceived) {
                            return 0;
                        }
                        if (mClosed) {
                            throw new IOException("Stream closed.");
                        }
                    }
                }
                
                // something in the buffer
                if (mInStderrBufferLen <= len) {
                    System.arraycopy(mInStderrBuffer, 0, buf, off, mInStderrBufferLen);
                    mInStderrBufferLen = 0;
                    checkAddWindow(mInStderrBufferLen);
                    return mInStderrBufferLen;
                } else {
                    System.arraycopy(mInStderrBuffer, 0, buf, off, len);
                    System.arraycopy(mInStderrBuffer, len, mInStderrBuffer, 0, mInStderrBufferLen - len);
                    mInStderrBufferLen -= len;
                    checkAddWindow(len);
                    return len;
                }
            }
        }

        public void
        close ()
        {
            Channel.this.close();
        }
    }
    
    private class ChannelOutputStream
        extends OutputStream
    {
        public void
        write (int c)
            throws IOException
        {
            byte[] b = new byte[1];
            b[0] = (byte) c;
            write(b, 0, 1);
        }
        
        public void
        write (byte[] buf, int off, int len)
            throws IOException
        {
            synchronized (mOutBufferLock) {
                while (len > 0) {
                    int n = waitForSendWindow(len);
                    if (n == 0) {
                        // closed, or EOF
                        throw new IOException("Stream is closed.");
                    }
                    
                    Message m = new Message();
                    m.putByte(MessageType.CHANNEL_DATA);
                    m.putInt(mRemoteChanID);
                    m.putByteString(buf, off, n);
                    mTransport.sendUserMessage(m, DEFAULT_TIMEOUT);
                    
                    off += n;
                    len -= n;
                }
            }
        }
        
        public void
        close ()
        {
            Channel.this.close();
        }
    }
    
    private class ChannelStderrOutputStream
        extends OutputStream
    {
        public void
        write (int c)
        throws IOException
        {
            byte[] b = new byte[1];
            b[0] = (byte) c;
            write(b, 0, 1);
        }
    
        public void
        write (byte[] buf, int off, int len)
            throws IOException
        {
            synchronized (mOutBufferLock) {
                while (len > 0) {
                    int n = waitForSendWindow(len);
                    if (n == 0) {
                        // closed, or EOF
                        throw new IOException("Stream is closed.");
                    }
                    
                    Message m = new Message();
                    m.putByte(MessageType.CHANNEL_EXTENDED_DATA);
                    m.putInt(mRemoteChanID);
                    m.putInt(1);
                    m.putByteString(buf, off, n);
                    mTransport.sendUserMessage(m, DEFAULT_TIMEOUT);
                    
                    off += n;
                    len -= n;
                }
            }
        }
    
        public void
        close ()
        {
            Channel.this.close();
        }
    }
    
    
    /**
     * Request a pseudo-terminal from the server.  This is usually used right
     * after creating a client channel, to ask the server to provide some
     * basic terminal semantics for a shell invoked with {@link #invokeShell}.
     * It isn't necessary (or desirable) to call this method if you're going
     * to execute a single command with {@link #execCommand}.
     * 
     * @param term the terminal type to emulate (for example, <code>"vt100"</code>)
     * @param width width (in characters) of the terminal screen
     * @param height height (in characters) of the terminal screen
     * @param timeout_ms time (in milliseconds) to wait for a response
     * @return true if the operation succeeded; false if not
     * @throws IOException if an exception occurred while making the request
     */
    public boolean
    getPTY (String term, int width, int height, int timeout_ms)
        throws IOException
    {
        synchronized (mLock) {
            if (mClosed || mEOFReceived || mEOFSent || !mActive) {
                throw new SSHException("Channel is not open");
            }
            
            Message m = new Message();
            m.putByte(MessageType.CHANNEL_REQUEST);
            m.putInt(mRemoteChanID);
            m.putString("pty-req");
            m.putBoolean(true);
            m.putString(term);
            m.putInt(width);
            m.putInt(height);
            // pixel height, width (usually useless)
            m.putInt(0);
            m.putInt(0);
            m.putString("");
            
            mEvent.clear();
            mTransport.sendUserMessage(m, timeout_ms);
        
            if (! waitForEvent(mEvent, timeout_ms)) {
                return false;
            }
            if (! mActive) {
                return false;
            }
            return true;
        }
    }
    
    /**
     * Request an interactive shell session on this channel.  If the server
     * allows it, the channel will then be directly connected to the stdin,
     * stdout, and stderr of the shell.
     * 
     * <p>Normally you would call {@link #getPTY} before this, in which case
     * the shell will operate through the pty, and the channel will be
     * connected to the stdin and stdout of the pty.
     * 
     * @param timeout_ms time (in milliseconds) to wait for a response
     * @return true if the operation succeeded; false if not
     * @throws IOException if an exception occurred while making the request
     */
    public boolean
    invokeShell (int timeout_ms)
        throws IOException
    {
        synchronized (mLock) {
            if (mClosed || mEOFReceived || mEOFSent || ! mActive) {
                throw new SSHException("Channel is not open");
            }
            
            Message m = new Message();
            m.putByte(MessageType.CHANNEL_REQUEST);
            m.putInt(mRemoteChanID);
            m.putString("shell");
            m.putBoolean(true);
            
            mEvent.clear();
            mTransport.sendUserMessage(m, timeout_ms);
            if (! waitForEvent(mEvent, timeout_ms)) {
                return false;
            }
            if (! mActive) {
                return false;
            }
            return true;
        }
    }

    /**
     * Set a timeout on read operations.  If <code>timeout_ms</code> is zero,
     * no timeout is set, and reads from this channel will block until there
     * is data available (or the channel is closed or reaches EOF).  If
     * <code>timeout_ms</code> is greater than zero, subsequent reads from
     * this channel's input streams will throw SocketTimeoutException if no
     * data is ready within the timeout period.
     * 
     * <p>By default, there is no timeout set, and read operations block
     * indefinitely.
     * 
     * @param timeout_ms timeout (in milliseconds), or zero
     */
    public void
    setTimeout (int timeout_ms)
    {
        synchronized (mInBufferLock) {
            if (timeout_ms < 0) {
                timeout_ms = 0;
            }
            mTimeout = timeout_ms;
        }
    }
    
    /**
     * Return the read timeout previously set with {@link #setTimeout}.
     * 
     * @return timeout (in milliseconds)
     */
    public int
    getTimeout ()
    {
        synchronized (mInBufferLock) {
            return mTimeout;
        }
    }
    
    /**
     * Return an InputStream for reading data from this channel.  If
     * {@link #setCombineStderr} has been turned on, the stream will contain
     * a combination of data from the primary stream. and from any out-of-band
     * "stderr" stream.  Otherwise, the "stderr" stream must be fetched
     * separately using {@link #getStderrInputStream}.
     * 
     * @return the InputStream for reading from this channel
     */
    public InputStream
    getInputStream ()
    {
        return new ChannelInputStream();
    }
    
    /**
     * Return an InputStream for reading data from the "stderr" stream of
     * this channel.  If {@link #setCombineStderr} has been turned on, or
     * you are using a pty, no data will ever arrive over this stream.
     * 
     * @return the InputStream for reading data from the "stderr" stream of
     *     this channel
     */
    public InputStream
    getStderrInputStream ()
    {
        return new ChannelStderrInputStream();
    }
    
    /**
     * Return an OutputStream for writing data into this channel.
     * 
     * @return the OutputStream for writing to this channel
     */
    public OutputStream
    getOutputStream ()
    {
        return new ChannelOutputStream();
    }
    
    /**
     * Return an OutputStream for writing data into the "stderr" stream of
     * this channel.  Normally this is only useful in server mode, when the
     * client did not request a pty.
     * 
     * @return the OutputStream for writing to the "stderr" stream of this
     *     channel
     */
    public OutputStream
    getStderrOutputStream ()
    {
        return new ChannelStderrOutputStream();
    }
    
    /**
     * Set whether stderr should be combined into stdout on this channel.
     * The default is false, but in some cases it may be convenient to have
     * both streams combined.
     * 
     * <p>If this is false, and {@link #execCommand} is called (or
     * {@link #invokeShell} with no pty), output to stderr will not show up
     * through the normal {@link #getInputStream} stream; instead, you must
     * use {@link #getStderrInputStream} to get stderr output.
     * 
     * <p>If this is true, data will never show up on {@link #getStderrInputStream},
     * but instead will be combined in the single normal input stream.
     * 
     * @param combine true if stdout and stderr input should be combined
     * @return the previous setting
     */
    public boolean
    setCombineStderr (boolean combine)
    {
        byte[] data = null;
        boolean old = false;
        
        synchronized (mInBufferLock) {
            synchronized (mInStderrBufferLock) {
                synchronized (mLock) {
                    old = mCombineStderr;
                    mCombineStderr = combine;
                }
                
                if (combine && ! old && (mInStderrBufferLen > 0)) {
                    // copy old stderr buffer into the primary buffer
                    data = new byte[mInStderrBufferLen];
                    System.arraycopy(mInStderrBuffer, 0, data, 0, mInStderrBufferLen);
                    mInStderrBufferLen = 0;
                }
            }
        }
        
        if (data != null) {
            feed(data);
        }
        return old;
    }
    
    /**
     * Close the channel.  All future read/write operations on the channel
     * will fail.  The remote end will receive no more data (after queued data
     * is flushed).  Channels are automatically closed when their
     * {@link Transport} is closed.
     */
    public void
    close ()
    {
        synchronized (mLock) {
            if (! mActive || mClosed) {
                return;
            }
            
            try {
                sendEOF();
            
                Message m = new Message();
                m.putByte(MessageType.CHANNEL_CLOSE);
                m.putInt(mRemoteChanID);
                mTransport.sendUserMessage(m, DEFAULT_TIMEOUT);
            } catch (IOException x) {
                mLog.debug("I/O exception while sending EOF/close");
            }
            
            setClosed();
            /* can't unlink from the Transport yet -- the remote side may
             * still try to send meta-data (exit-status, etc)
             */
        }
    }
    
    public boolean
    handleMessage (byte ptype, Message m)
        throws IOException
    {
        switch (ptype) {
        case MessageType.CHANNEL_WINDOW_ADJUST:
            return handleWindowAdjust(m);
        case MessageType.CHANNEL_DATA:
            return handleData(m);
        case MessageType.CHANNEL_EXTENDED_DATA:
            return handleExtendedData(m);
        case MessageType.CHANNEL_EOF:
            return handleEOF(m);
        case MessageType.CHANNEL_CLOSE:
            return handleClose(m);
        case MessageType.CHANNEL_REQUEST:
            return handleRequest(m);
        case MessageType.CHANNEL_SUCCESS:
            return handleSuccess(m);
        case MessageType.CHANNEL_FAILURE:
            return handleFailure(m);
        default:
            return false;
        }
    }
    
    

    /* package */ void
    setTransport (TransportInterface t, LogSink log)
    {
        mTransport = t;
        mLog = log;
    }

    /* package */ void
    setWindow (int windowSize, int maxPacketSize)
    {
        mInWindowSize = windowSize;
        mInMaxPacketSize = maxPacketSize;
        mInWindowThreshold = windowSize / 10;
        mInWindowSoFar = 0;
        mLog.debug("Max packet in: " + maxPacketSize + " bytes");
    }
    
    /* package */ void
    setRemoteChannel (int serverChanID, int serverWindowSize, int serverMaxPacketSize)
    {
        mRemoteChanID = serverChanID;
        mOutWindowSize = serverWindowSize;
        mOutMaxPacketSize = serverMaxPacketSize;
        if (mOutMaxPacketSize < MIN_PACKET_SIZE) {
            mOutMaxPacketSize = MIN_PACKET_SIZE;
        }
        mActive = true;
        mLog.debug("Max packet out: " + serverMaxPacketSize + " bytes");
    }
    
    /* package */ void
    unlink ()
    {
        // server connection could die before we become active: still signal the close!
        synchronized (mLock) {
            if (mClosed) {
                return;
            }

            setClosed();
            mTransport.unlinkChannel(mChanID);
        }
    }
    
    
    
    // you are holding the lock.
    private void
    setClosed ()
    {
        mClosed = true;
        synchronized (mInBufferLock) {
            mInBufferLock.notifyAll();
        }
        synchronized (mInStderrBufferLock) {
            mInStderrBufferLock.notifyAll();
        }
        synchronized (mOutBufferLock) {
            mOutBufferLock.notifyAll();
        }
    }
    
    // you are holding the lock
    private void
    sendEOF ()
        throws IOException
    {
        if (mEOFSent) {
            return;
        }
        // in case we hit an error trying to send it:
        mEOFSent = true;
        
        Message m = new Message();
        m.putByte(MessageType.CHANNEL_EOF);
        m.putInt(mRemoteChanID);
        mTransport.sendUserMessage(m, DEFAULT_TIMEOUT);
        mLog.debug("EOF sent");
    }

    /**
     * Wait for an event to trigger, up to an optional timeout.  If the
     * channel goes inactive (dead), it will return prematurely within the
     * next tenth of a second.
     * It will also return prematurely if the thread is interrupted.
     *  
     * @param e the event to wait on
     * @param timeout_ms maximum time to wait (in milliseconds); -1 to wait
     *     forever
     * @return true if the event was triggered or the transport died; false if
     *     the timeout occurred or the thread was interrupted
     */
    private boolean
    waitForEvent (Event e, int timeout_ms)
    {
        long deadline = System.currentTimeMillis() + timeout_ms;
        while (! e.isSet()) {
            try {
                int span = (timeout_ms >= 0) ? (int)(deadline - System.currentTimeMillis()) : 100;
                if (span < 0) {
                    return false;
                }
                if (span > 100) {
                    span = 100;
                }
                if (span > 0) {
                    e.waitFor(span);
                }
            } catch (InterruptedException x) {
                // just remember it
                Thread.currentThread().interrupt();
                return false;
            }

            if (! mActive) {
                return true;
            }
        }
        return true;
    }
    
    // you're already holding mInBufferLock
    private void
    checkAddWindow (int nbytes)
    {
        synchronized (mLock) {
            if (mClosed || mEOFReceived || !mActive) {
                return;
            }
            mInWindowSoFar += nbytes;
            if (mInWindowSoFar > mInWindowThreshold) {
                Message m = new Message();
                m.putByte(MessageType.CHANNEL_WINDOW_ADJUST);
                m.putInt(mRemoteChanID);
                m.putInt(mInWindowSoFar);
                try {
                    mTransport.sendUserMessage(m, DEFAULT_TIMEOUT);
                } catch (IOException x) {
                    mLog.debug("I/O Exception while sending window adjustment");
                }
                mInWindowSoFar = 0;
            }
        }
    }
    
    /**
     * Wait for the send window to open up, and allocate up to
     * <code>size</code> bytes for transmission.  If no space is available,
     * this method will block until space opens up, or the channel is closed.
     * 
     * You are holding mOutBufferLock.
     * 
     * @param size number of bytes desired
     * @return number of bytes allocated (may be less than requested)
     */
    private int
    waitForSendWindow (int size)
    {
        while (mOutWindowSize == 0) {
            synchronized (mLock) {
                if (mClosed || mEOFSent) {
                    return 0;
                }
            }
            
            try {
                mOutBufferLock.wait();
            } catch (InterruptedException x) { }
        }
        
        synchronized (mLock) {
            if (mClosed || mEOFSent) {
                return 0;
            }
        }
        
        if (mOutWindowSize < size) {
            size = mOutWindowSize;
        }
        if (mOutMaxPacketSize - 64 < size) {
            size = mOutMaxPacketSize - 64;
        }
        mOutWindowSize -= size;
        return size;
    }
    
    private void
    feed (byte[] data)
    {
        synchronized (mInBufferLock) {
            while (mInBufferLen + data.length > mInBuffer.length) {
                byte[] newbuf = new byte[4 * mInBuffer.length];
                System.arraycopy(mInBuffer, 0, newbuf, 0, mInBufferLen);
                mInBuffer = newbuf;
            }
            System.arraycopy(data, 0, mInBuffer, mInBufferLen, data.length);
            mInBufferLen += data.length;
            mInBufferLock.notifyAll();
        }
    }
    
    private void
    feedStderr (byte[] data)
    {
        synchronized (mInStderrBufferLock) {
            while (mInStderrBufferLen + data.length > mInStderrBuffer.length) {
                byte[] newbuf = new byte[4 * mInStderrBuffer.length];
                System.arraycopy(mInStderrBuffer, 0, newbuf, 0, mInStderrBufferLen);
                mInStderrBuffer = newbuf;
            }
            System.arraycopy(data, 0, mInStderrBuffer, mInStderrBufferLen, data.length);
            mInStderrBufferLen += data.length;
            mInStderrBufferLock.notifyAll();
        }
    }
    
    private boolean
    handleWindowAdjust (Message m)
    {
        int nbytes = m.getInt();
        synchronized (mOutBufferLock) {
            mOutWindowSize += nbytes;
            mOutBufferLock.notifyAll();
        }
        return true;
    }
    
    private boolean
    handleData (Message m)
    {
        feed(m.getByteString());
        return true;
    }
    
    private boolean
    handleExtendedData (Message m)
    {
        int code = m.getInt();
        byte[] data = m.getByteString();
        if (code != 1) {
            mLog.error("Unknown extended_data type " + code + "; discarding");
            return true;
        }
        
        if (mCombineStderr) {
            feed(data);
        } else {
            feedStderr(data);
        }
        
        return true;
    }
    
    private boolean
    handleEOF (Message m)
    {
        synchronized (mLock) {
            if (! mEOFReceived) {
                mEOFReceived = true;
                synchronized (mInBufferLock) {
                    mInBufferLock.notifyAll();
                }
                synchronized (mInStderrBufferLock) {
                    mInStderrBufferLock.notifyAll();
                }
            }
        }
        mLog.debug("EOF received");
        return true;
    }
    
    private boolean
    handleClose (Message m)
    {
        close();
        synchronized (mLock) {
            mTransport.unlinkChannel(mChanID);
        }
        return true;
    }
    
    private boolean
    handleRequest (Message m)
        throws IOException
    {
        String key = m.getString();
        boolean wantReply = m.getBoolean();
        boolean ok = false;
        
        if (key.equals("exit-status")) {
            mExitStatus = m.getInt();
            mStatusEvent.set();
            ok = true;
        } else if (key.equals("xon-xoff")) {
            // ignore
            ok = true;
        } else {
            // FIXME: lots of server events here
            mLog.debug("Unhandled channel request '" + key + "'");
            ok = false;
        }
        
        if (wantReply) {
            Message mx = new Message();
            mx.putByte(ok ? MessageType.CHANNEL_SUCCESS : MessageType.CHANNEL_FAILURE);
            mx.putInt(mRemoteChanID);
            mTransport.sendUserMessage(mx, DEFAULT_TIMEOUT);
        }
        return true;
    }
    
    private boolean
    handleSuccess (Message m)
    {
        mLog.debug("Secsh channel " + mChanID + " request ok");
        mEvent.set();
        return true;
    }
    
    private boolean
    handleFailure (Message m)
    {
        mLog.debug("Secsh channel " + mChanID + " request failed.");
        close();
        return true;
    }
    
    
    
    private int mChanID;
    private int mRemoteChanID;
    private boolean mActive;
    private boolean mClosed;
    private boolean mEOFReceived;
    private boolean mEOFSent;
    private boolean mCombineStderr;
    private Object mLock;
    private Event mEvent;
    private TransportInterface mTransport;
    private LogSink mLog;
    
    private int mInWindowSize;
    private int mInMaxPacketSize;
    private int mInWindowThreshold;     // bytes we must receive before we bother to send a window update
    private int mInWindowSoFar;
    
    private int mOutWindowSize;
    private int mOutMaxPacketSize;
    
    private byte[] mInBuffer;
    private int mInBufferLen;
    private Object mInBufferLock;
    private byte[] mInStderrBuffer;
    private int mInStderrBufferLen;
    private Object mInStderrBufferLock;
    private Object mOutBufferLock;
    
    private int mExitStatus = -1;
    private Event mStatusEvent;
    private int mTimeout;
 
    // lower bound on the "max packet size" we'll allow from the server
    private static final int MIN_PACKET_SIZE = 1024;

    // default timeout for sending out-of-band messages like "close"
    private static final int DEFAULT_TIMEOUT = 100;
}
