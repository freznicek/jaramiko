/*
 * Copyright (C) 2005-2006 Robey Pointer <robey@lag.net>
 *
 * This file is part of jaramiko.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package net.lag.jaramiko;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.List;

/*
 * locking order:  mInStream.mBufferLock, mStderrInStream.mBufferLock, mLock
 *
 * channel methods should not be called while holding a transport lock.
 *
 * mOutBufferLock protects: mOutWindowSize, outbound packets
 * mLock protects: mActive, mClosed, mEOFReceived, mEOFSent, mCombineStderr
 */

/**
 * A secure tunnel across an SSH {@link Transport}. A Channel is meant to behave
 * like a socket. It has an InputStream and OutputStream, and may have an input
 * timeout set on it, just like a java socket.
 * 
 * Because SSH2 has a windowing kind of flow control, if you stop reading data
 * from a Channel and its buffer fills up, the server will be unable to send you
 * any more data until you read some of it. (This won't affect other channels on
 * the same transport -- all channels on a single transport are flow-controlled
 * independently.) Similarly, if the server isn't reading data you send, calls
 * to <code>write()</code> on the OutputStream may block. This is exactly like a
 * normal network socket behaves, so it shouldn't be too surprising.
 */
public class Channel {
    /* package */static class Factory implements ChannelFactory {
        public Channel createChannel(String kind, int chanid, List params) {
            return new Channel(chanid, kind, params);
        }

        public Channel createChannel(String kind, int chanid, Message params) {
            return new Channel(chanid, kind, null);
        }
    }

    private class ChannelInputStream extends InputStream {
        public ChannelInputStream() {
            mBuffer = new byte[64];
            mBufferLen = 0;
            mBufferLock = new Object();
        }

        @Override
        public int available() {
            synchronized (mBufferLock) {
                return mBufferLen;
            }
        }

        @Override
        public int read() throws IOException {
            byte[] b = new byte[1];
            if (read(b, 0, 1) < 1) {
                return -1;
            }
            return b[0] & 0xff;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            int ack = 0;

            synchronized (mBufferLock) {
                if (mBufferLen == 0) {
                    int timeout = mTimeout;
                    while (mBufferLen == 0) {
                        synchronized (mLock) {
                            if (mClosed || mEOFReceived) {
                                break;
                            }
                        }

                        long then = System.currentTimeMillis();
                        try {
                            mBufferLock.wait(timeout);
                        } catch (InterruptedException x) {}
                        if (mTimeout > 0) {
                            timeout -= System.currentTimeMillis() - then;
                            if (timeout <= 0) {
                                throw new InterruptedIOException("timeout");
                            }
                        }
                    }

                    if (mBufferLen == 0) {
                        synchronized (mLock) {
                            if (mEOFReceived) {
                                return -1;
                            }
                            if (mClosed) {
                                throw new IOException("Stream closed.");
                            }
                        }
                    }
                }

                // something in the buffer
                if (mBufferLen <= len) {
                    System.arraycopy(mBuffer, 0, buf, off, mBufferLen);
                    len = mBufferLen;
                    mBufferLen = 0;
                } else {
                    System.arraycopy(mBuffer, 0, buf, off, len);
                    System.arraycopy(mBuffer, len, mBuffer, 0, mBufferLen - len);
                    mBufferLen -= len;
                }

                ack = checkAddWindow(len);
            }

            // can do this outside of the lock
            if (ack > 0) {
                Message m = new Message();
                m.putByte(MessageType.CHANNEL_WINDOW_ADJUST);
                m.putInt(mRemoteChanID);
                m.putInt(ack);
                mTransport.sendUserMessage(m, DEFAULT_TIMEOUT);
            }

            return len;
        }

        @Override
        public void close() {
            Channel.this.close();
        }

        private byte[] mBuffer;
        private int mBufferLen;
        private Object mBufferLock;
    }

    private class ChannelOutputStream extends OutputStream {
        public ChannelOutputStream(boolean stderr) {
            mStderr = stderr;
        }

        @Override
        public void write(int c) throws IOException {
            byte[] b = new byte[1];
            b[0] = (byte) c;
            write(b, 0, 1);
        }

        @Override
        public void write(byte[] buf, int off, int len) throws IOException {
            synchronized (mOutBufferLock) {
                while (len > 0) {
                    int n = waitForSendWindow(len);
                    if (n == 0) {
                        // closed, or EOF
                        throw new IOException("Stream is closed.");
                    }

                    Message m = new Message();
                    if (mStderr) {
                        m.putByte(MessageType.CHANNEL_EXTENDED_DATA);
                        m.putInt(mRemoteChanID);
                        m.putInt(1);
                    } else {
                        m.putByte(MessageType.CHANNEL_DATA);
                        m.putInt(mRemoteChanID);
                    }
                    m.putByteString(buf, off, n);
                    mTransport.sendUserMessage(m, DEFAULT_TIMEOUT);

                    off += n;
                    len -= n;
                }
            }
        }

        @Override
        public void close() {
            Channel.this.close();
        }

        private boolean mStderr;
    }

    /**
     * Client-mode constructor for a Channel. The parameters (if any) are passed
     * in as a list directly from the application request.
     * 
     * @param chanid
     *            channel ID
     * @param kind
     *            kind of channel
     * @param params
     *            the parameters this channel was opened with
     */
    protected Channel(int chanid, String kind, List params) {
        mChanID = chanid;
        mKind = kind;
        mParams = params;
        mActive = false;
        mClosed = false;
        mEOFReceived = false;
        mEOFSent = false;
        mCombineStderr = false;
        mLock = new Object();
        mEvent = new Event();
        mNotifyObject = null;

        mInStream = new ChannelInputStream();
        mStderrInStream = new ChannelInputStream();
        mOutStream = new ChannelOutputStream(false);
        mStderrOutStream = new ChannelOutputStream(true);
        mOutBufferLock = new Object();

        mStatusEvent = new Event();
        mTimeout = 0; // infinite, in java-speek
    }

    /**
     * Request a pseudo-terminal from the server. This is usually used right
     * after creating a client channel, to ask the server to provide some basic
     * terminal semantics for a shell invoked with {@link #invokeShell}. It
     * isn't necessary (or desirable) to call this method if you're going to
     * execute a single command with {@link #execCommand}.
     * 
     * <p>
     * Normally this method will wait for a server response to verify that it
     * succeeded. You may pass a timeout of <code>0</code> to make the request
     * without waiting for a response.
     * 
     * @param term
     *            the terminal type to emulate (for example,
     *            <code>"vt100"</code>)
     * @param width
     *            width (in characters) of the terminal screen
     * @param height
     *            height (in characters) of the terminal screen
     * @param modes
     *            any requested terminal modes, or null if none are desired
     * @param timeout_ms
     *            time (in milliseconds) to wait for a response; -1 to wait
     *            forever; 0 to avoid waiting for a response
     * @throws IOException
     *             if an exception occurred while making the request
     */
    public void getPTY(String term, int width, int height, TerminalModes modes,
            int timeout_ms) throws IOException {
        synchronized (mLock) {
            if (mClosed || mEOFReceived || mEOFSent || !mActive) {
                throw new SSHException("Channel is not open");
            }

            Message m = new Message();
            m.putByte(MessageType.CHANNEL_REQUEST);
            m.putInt(mRemoteChanID);
            m.putString("pty-req");
            m.putBoolean(timeout_ms != 0);
            m.putString(term);
            m.putInt(width);
            m.putInt(height);
            // pixel height, width (usually useless)
            m.putInt(0);
            m.putInt(0);
            if (modes == null) {
                m.putByteString(new byte[0]);
            } else {
                m.putByteString(modes.toBytes());
            }

            mEvent.clear();
            mTransport.sendUserMessage(m, -1);
        }

        if (timeout_ms != 0) {
            waitForEvent(mEvent, timeout_ms);
        }
    }

    /**
     * Request a pseudo-terminal from the server. This is usually used right
     * after creating a client channel, to ask the server to provide some basic
     * terminal semantics for a shell invoked with {@link #invokeShell}. It
     * isn't necessary (or desirable) to call this method if you're going to
     * execute a single command with {@link #execCommand}.
     * 
     * <p>
     * Normally this method will wait for a server response to verify that it
     * succeeded. You may pass a timeout of <code>0</code> to make the request
     * without waiting for a response.
     * 
     * @param term
     *            the terminal type to emulate (for example,
     *            <code>"vt100"</code>)
     * @param width
     *            width (in characters) of the terminal screen
     * @param height
     *            height (in characters) of the terminal screen
     * @param timeout_ms
     *            time (in milliseconds) to wait for a response; -1 to wait
     *            forever; 0 to avoid waiting for a response
     * @throws IOException
     *             if an exception occurred while making the request
     */
    public void getPTY(String term, int width, int height, int timeout_ms)
            throws IOException {
        getPTY(term, width, height, null, timeout_ms);
    }

    /**
     * Request an interactive shell session on this channel. If the server
     * allows it, the channel will then be directly connected to the stdin,
     * stdout, and stderr of the shell.
     * 
     * <p>
     * A typical usage would call {@link #getPTY} before this, in which case the
     * shell will operate through the pty, and the channel will be connected to
     * the stdin and stdout of the pty.
     * 
     * <p>
     * Normally this method will wait for a server response to verify that it
     * succeeded. You may pass a timeout of <code>0</code> to make the request
     * without waiting for a response.
     * 
     * @param timeout_ms
     *            time (in milliseconds) to wait for a response; -1 to wait
     *            forever; 0 to avoid waiting for a response
     * @throws IOException
     *             if an exception occurred while making the request
     */
    public void invokeShell(int timeout_ms) throws IOException {
        synchronized (mLock) {
            if (mClosed || mEOFReceived || mEOFSent || !mActive) {
                throw new SSHException("Channel is not open");
            }

            Message m = new Message();
            m.putByte(MessageType.CHANNEL_REQUEST);
            m.putInt(mRemoteChanID);
            m.putString("shell");
            m.putBoolean(timeout_ms != 0);

            mEvent.clear();
            mTransport.sendUserMessage(m, -1);
        }

        if (timeout_ms != 0) {
            waitForEvent(mEvent, timeout_ms);
        }
    }

    /**
     * Execute a command on the server. If the server allows it, the channel
     * will then be directly connected to the stdin, stdout, and stderr of the
     * command being executed.
     * 
     * <p>
     * Normally this method will wait for a server response to verify that it
     * succeeded. You may pass a timeout of <code>0</code> to make the request
     * without waiting for a response.
     * 
     * @param command
     *            a shell command to execute
     * @param timeout_ms
     *            time (in milliseconds) to wait for a response; -1 to wait
     *            forever; 0 to avoid waiting for a response
     * @throws IOException
     *             if an exception occurred while making the request
     */
    public void execCommand(String command, int timeout_ms) throws IOException {
        synchronized (mLock) {
            if (mClosed || mEOFReceived || mEOFSent || !mActive) {
                throw new SSHException("Channel is not open");
            }

            Message m = new Message();
            m.putByte(MessageType.CHANNEL_REQUEST);
            m.putInt(mRemoteChanID);
            m.putString("exec");
            m.putBoolean(timeout_ms != 0);
            m.putString(command);

            mEvent.clear();
            mTransport.sendUserMessage(m, -1);
        }

        if (timeout_ms != 0) {
            waitForEvent(mEvent, timeout_ms);
        }
    }

    /**
     * Request a subsystem on the server (for example, <code>"sftp"</code>). If
     * the server allows it, the channel will then be directly connected to the
     * requested subsystem.
     * 
     * <p>
     * Normally this method will wait for a server response to verify that it
     * succeeded. You may pass a timeout of <code>0</code> to make the request
     * without waiting for a response.
     * 
     * @param subsystem
     *            name of the subsystem being requested
     * @param timeout_ms
     *            time (in milliseconds) to wait for a response; -1 to wait
     *            forever; 0 to avoid waiting for a response
     * @throws IOException
     *             if an exception occurred while making the request
     */
    public void invokeSubsystem(String subsystem, int timeout_ms)
            throws IOException {
        synchronized (mLock) {
            if (mClosed || mEOFReceived || mEOFSent || !mActive) {
                throw new SSHException("Channel is not open");
            }

            Message m = new Message();
            m.putByte(MessageType.CHANNEL_REQUEST);
            m.putInt(mRemoteChanID);
            m.putString("subsystem");
            m.putBoolean(timeout_ms != 0);
            m.putString(subsystem);

            mEvent.clear();
            mTransport.sendUserMessage(m, -1);
        }

        if (timeout_ms != 0) {
            waitForEvent(mEvent, timeout_ms);
        }
    }

    /**
     * Resize the pseudo-terminal. This can be used to change the width and
     * height of the terminal emulation created by a previous {@link #getPTY}
     * call.
     * 
     * <p>
     * Normally this method will wait for a server response to verify that it
     * succeeded. You may pass a timeout of <code>0</code> to make the request
     * without waiting for a response.
     * 
     * @param width
     *            new width (in characters) of the terminal
     * @param height
     *            new height (in characters) of the terminal
     * @param timeout_ms
     *            time (in milliseconds) to wait for a response; -1 to wait
     *            forever; 0 to avoid waiting for a response
     * @throws IOException
     *             if an exception occurred while making the request
     */
    public void resizePTY(int width, int height, int timeout_ms)
            throws IOException {
        synchronized (mLock) {
            if (mClosed || mEOFReceived || mEOFSent || !mActive) {
                throw new SSHException("Channel is not open");
            }

            Message m = new Message();
            m.putByte(MessageType.CHANNEL_REQUEST);
            m.putInt(mRemoteChanID);
            m.putString("window-change");
            m.putBoolean(timeout_ms != 0);
            m.putInt(width);
            m.putInt(height);
            m.putInt(0);
            m.putInt(0);

            mEvent.clear();
            mTransport.sendUserMessage(m, timeout_ms);
        }

        if (timeout_ms != 0) {
            waitForEvent(mEvent, timeout_ms);
        }
    }

    /**
     * Return the exit status from the process on the server. This is mostly
     * useful for retrieving the results of an {@link #execCommand}. If the
     * command hasn't finished yet, this method will wait up to
     * <code>timeout_ms</code> for it to complete. If no exit status is sent
     * within the timeout, an {@link SSHException} will be thrown.
     * 
     * @param timeout_ms
     *            time (in milliseconds) to wait for the exit status to be sent;
     *            -1 to wait forever
     * @return the exit status
     * @throws SSHException
     *             if no exit status was sent before the timeout, or the channel
     *             was closed
     */
    public int getExitStatus(int timeout_ms) throws SSHException {
        waitForEvent(mStatusEvent, timeout_ms);
        return mExitStatus;
    }

    /**
     * Send the exit status of an executed command to the client. (This really
     * only makes sense in server mode.) Many clients expect to get some sort of
     * status code back from an executed command after it completes.
     * 
     * @param status
     *            the exit code of the process
     * @throws IOException
     *             if an exception occurred while sending the status code
     */
    public void sendExitStatus(int status) throws IOException {
        synchronized (mLock) {
            // in many cases, the channel will not still be open here. that's
            // fine.
            Message m = new Message();
            m.putByte(MessageType.CHANNEL_REQUEST);
            m.putInt(mRemoteChanID);
            m.putString("exit-status");
            m.putBoolean(false);
            m.putInt(status);
            mTransport.sendUserMessage(m, DEFAULT_TIMEOUT);
        }
    }

    /**
     * Send a generic channel request. There is no reason to use this if you are
     * communicating with a standard SSH server, but it can be useful for
     * implementing other protocols across SSH.
     * 
     * <p>
     * Normally this method will wait for a server response to verify that it
     * succeeded. You may pass a timeout of <code>0</code> to make the request
     * without waiting for a response.
     * 
     * @param type
     *            the type of the message (an arbitrary string)
     * @param data
     *            data to be sent along with the request (can be null if no
     *            extra data is to be sent)
     * @param timeout_ms
     *            time (in milliseconds) to wait to send the message; -1 to wait
     *            forever; 0 to avoid waiting for a response
     * @throws IOException
     *             if an exception occurred while making the request
     */
    public void sendChannelRequest(String type, List<Object> data,
            int timeout_ms) throws IOException {
        synchronized (mLock) {
            if (mClosed || mEOFReceived || mEOFSent || !mActive) {
                throw new SSHException("Channel is not open");
            }

            Message m = new Message();
            m.putByte(MessageType.CHANNEL_REQUEST);
            m.putInt(mRemoteChanID);
            m.putString(type);
            m.putBoolean(timeout_ms != 0);
            if (data != null) {
                m.putAll(data);
            }

            mEvent.clear();
            mTransport.sendUserMessage(m, timeout_ms);
            if (timeout_ms != 0) {
                waitForEvent(mEvent, timeout_ms);
            }
        }
    }

    /**
     * Return the arbitrary string identifying the "type" for this channel. For
     * normal SSH channels, this will usually be <code>"session"</code>.
     * 
     * @return the kind of SSH channel
     */
    public String getKind() {
        return mKind;
    }

    /**
     * Return a list of parameters passed to the channel. In most cases this
     * will be null because most SSH channels don't take parameters.
     * 
     * @return the channel parameters
     */
    public List getParams() {
        return mParams;
    }

    /**
     * Set a timeout on read operations. If <code>timeout_ms</code> is zero, no
     * timeout is set, and reads from this channel will block until there is
     * data available (or the channel is closed or reaches EOF). If
     * <code>timeout_ms</code> is greater than zero, subsequent reads from this
     * channel's input streams will throw InterruptedIOException if no data is
     * ready within the timeout period.
     * 
     * <p>
     * By default, there is no timeout set, and read operations block
     * indefinitely.
     * 
     * @param timeout_ms
     *            timeout (in milliseconds), or zero
     */
    public void setTimeout(int timeout_ms) {
        if (timeout_ms < 0) {
            timeout_ms = 0;
        }

        synchronized (mInStream.mBufferLock) {
            synchronized (mStderrInStream.mBufferLock) {
                mTimeout = timeout_ms;
            }
        }
    }

    /**
     * Return the read timeout previously set with {@link #setTimeout}.
     * 
     * @return timeout (in milliseconds)
     */
    public int getTimeout() {
        synchronized (mInStream.mBufferLock) {
            synchronized (mStderrInStream.mBufferLock) {
                return mTimeout;
            }
        }
    }

    /**
     * Return an InputStream for reading data from this channel. If
     * {@link #setCombineStderr} has been turned on, the stream will contain a
     * combination of data from the primary stream. and from any out-of-band
     * "stderr" stream. Otherwise, the "stderr" stream must be fetched
     * separately using {@link #getStderrInputStream}.
     * 
     * @return the InputStream for reading from this channel
     */
    public InputStream getInputStream() {
        return mInStream;
    }

    /**
     * Return an InputStream for reading data from the "stderr" stream of this
     * channel. If {@link #setCombineStderr} has been turned on, or you are
     * using a pty, no data will ever arrive over this stream.
     * 
     * @return the InputStream for reading data from the "stderr" stream of this
     *         channel
     */
    public InputStream getStderrInputStream() {
        return mStderrInStream;
    }

    /**
     * Return an OutputStream for writing data into this channel.
     * 
     * @return the OutputStream for writing to this channel
     */
    public OutputStream getOutputStream() {
        return mOutStream;
    }

    /**
     * Return an OutputStream for writing data into the "stderr" stream of this
     * channel. Normally this is only useful in server mode, when the client did
     * not request a pty.
     * 
     * @return the OutputStream for writing to the "stderr" stream of this
     *         channel
     */
    public OutputStream getStderrOutputStream() {
        return mStderrOutStream;
    }

    /**
     * Set whether stderr should be combined into stdout on this channel. The
     * default is false, but in some cases it may be convenient to have both
     * streams combined.
     * 
     * <p>
     * If this is false, and {@link #execCommand} is called (or
     * {@link #invokeShell} with no pty), output to stderr will not show up
     * through the normal {@link #getInputStream} stream; instead, you must use
     * {@link #getStderrInputStream} to get stderr output.
     * 
     * <p>
     * If this is true, data will never show up on {@link #getStderrInputStream}
     * , but instead will be combined in the single normal input stream.
     * 
     * @param combine
     *            true if stdout and stderr input should be combined
     * @return the previous setting
     */
    public boolean setCombineStderr(boolean combine) {
        byte[] data = null;
        boolean old = false;

        synchronized (mInStream.mBufferLock) {
            synchronized (mStderrInStream.mBufferLock) {
                synchronized (mLock) {
                    old = mCombineStderr;
                    mCombineStderr = combine;
                }

                if (combine && !old && (mStderrInStream.mBufferLen > 0)) {
                    // copy old stderr buffer into the primary buffer
                    data = new byte[mStderrInStream.mBufferLen];
                    System.arraycopy(mStderrInStream.mBuffer, 0, data, 0,
                            mStderrInStream.mBufferLen);
                    mStderrInStream.mBufferLen = 0;
                }
            }
        }

        if (data != null) {
            feed(mInStream, data);
        }
        return old;
    }

    /**
     * Close the channel. All future read/write operations on the channel will
     * fail. The remote end will receive no more data (after queued data is
     * flushed). Channels are automatically closed when their {@link Transport}
     * is closed.
     */
    public void close() {
        synchronized (mLock) {
            if (!mActive || mClosed) {
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

            mClosed = true;
            /*
             * can't unlink from the Transport yet -- the remote side may still
             * try to send meta-data (exit-status, etc)
             */
        }

        notifyClosed();
    }

    /**
     * Return <code>true</code> if the channel is closed, either by the local or
     * remote side.
     * 
     * @return <code>true</code> if this channel is closed
     */
    public boolean isClosed() {
        synchronized (mLock) {
            return mClosed;
        }
    }

    /**
     * Shutdown the receiving side of this socket, closing the stream in the
     * incoming direction. After this call, future reads on this channel will
     * fail instantly.
     */
    public void shutdownRead() throws IOException {
        // fake it
        synchronized (mLock) {
            mEOFReceived = true;
        }
    }

    /**
     * Shutdown the sending side of this socket, closing the stream in the
     * outgoing direction. After this call, future writes on this channel will
     * fail instantly.
     * 
     * @throws IOException
     *             if an exception occurred
     */
    public void shutdownWrite() throws IOException {
        synchronized (mLock) {
            sendEOF();
        }
    }

    /**
     * Return the ID # for this channel. The channel ID is unique across a
     * {@link Transport} and usually a small number. It's also the number passed
     * to {@link ServerInterface#checkChannelRequest} when determining whether
     * to accept a channel request in server mode.
     * 
     * @return the channel ID
     */
    public int getID() {
        return mChanID;
    }

    /**
     * Set an object to be notified when new data arrives on the channel. For an
     * event-based server, it may be helpful to be notified through an object
     * instead of looping in a thread around a <code>read()</code> call.
     * 
     * <p>
     * Once a notify object is set, whenever new data arrives on this channel,
     * the notify object will be notified via a call to {@link Object#notifyAll}.
     * 
     * @param obj
     *            the object to notify
     */
    public void setNotifyObject(Object obj) {
        mNotifyObject = obj;
    }

    /**
     * Get the {@link Transport} this Channel is associated with.
     * 
     * @return this channel's Transport
     */
    public Transport getTransport() {
        return mTransport;
    }

    /**
     * Handle a custom channel request from the remote host. The default method
     * just returns <code>false</code> to reject the request.
     * 
     * @param type
     *            channel request type (an arbitrary string)
     * @param message
     *            an SSH Message object which may contain extra parameters for
     *            this request
     * @return true if the request was successful; false if not
     */
    protected boolean handleCustomRequest(String type, Message message) {
        mLog.debug("Unhandled channel request '" + type + "'");
        return false;
    }

    /* package */boolean handleMessage(byte ptype, Message m)
            throws IOException {
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

    /* package */void setTransport(BaseTransport t, LogSink log) {
        mTransport = t;
        mLog = log;
    }

    /* package */void setWindow(int windowSize, int maxPacketSize) {
        // mInWindowSize = windowSize;
        // mInMaxPacketSize = maxPacketSize;
        mInWindowThreshold = windowSize / 10;
        mInWindowSoFar = 0;
        mLog.debug("Max packet in: " + maxPacketSize + " bytes");
    }

    /* package */void setRemoteChannel(int serverChanID, int serverWindowSize,
            int serverMaxPacketSize) {
        mRemoteChanID = serverChanID;
        mOutWindowSize = serverWindowSize;
        mOutMaxPacketSize = serverMaxPacketSize;
        if (mOutMaxPacketSize < MIN_PACKET_SIZE) {
            mOutMaxPacketSize = MIN_PACKET_SIZE;
        }
        mActive = true;
        mLog.debug("Max packet out: " + serverMaxPacketSize + " bytes");
    }

    /* package */void setServer(ServerInterface server) {
        mServer = server;
    }

    /* package */void unlink() {
        // server connection could die before we become active: still signal the
        // close!
        synchronized (mLock) {
            if (mClosed) {
                return;
            }

            mClosed = true;
            mTransport.unlinkChannel(mChanID);
        }
        notifyClosed();
    }

    private void notifyClosed() {
        synchronized (mInStream.mBufferLock) {
            mInStream.mBufferLock.notifyAll();
        }
        synchronized (mStderrInStream.mBufferLock) {
            mStderrInStream.mBufferLock.notifyAll();
        }
        synchronized (mOutBufferLock) {
            mOutBufferLock.notifyAll();
        }
        if (mNotifyObject != null) {
            synchronized (mNotifyObject) {
                mNotifyObject.notifyAll();
            }
        }
    }

    // you are holding the lock
    private void sendEOF() throws IOException {
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
     * Wait for an event to trigger, up to an optional timeout. If the channel
     * goes inactive (dead), it will return prematurely within the next tenth of
     * a second. It will also return prematurely if the thread is interrupted.
     * 
     * @param e
     *            the event to wait on
     * @param timeout_ms
     *            maximum time to wait (in milliseconds); -1 to wait forever
     * @throws SSHException
     *             if the timeout occurs or the socket is closed
     */
    private void waitForEvent(Event e, int timeout_ms) throws SSHException {
        long deadline = System.currentTimeMillis() + timeout_ms;
        while (!e.isSet()) {
            try {
                int span = (timeout_ms >= 0) ? (int) (deadline - System
                        .currentTimeMillis()) : 100;
                if (span < 0) {
                    throw new SSHException("timeout");
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
                return;
            }

            synchronized (mLock) {
                if (mClosed) {
                    throw new SSHException("Request failed");
                }
            }
        }
    }

    // you're already holding mInBufferLock
    private int checkAddWindow(int nbytes) {
        synchronized (mLock) {
            if (mClosed || mEOFReceived || !mActive) {
                return 0;
            }

            mInWindowSoFar += nbytes;
            if (mInWindowSoFar <= mInWindowThreshold) {
                return 0;
            }
            int ack = mInWindowSoFar;
            mInWindowSoFar = 0;
            return ack;
        }
    }

    /**
     * Wait for the send window to open up, and allocate up to <code>size</code>
     * bytes for transmission. If no space is available, this method will block
     * until space opens up, or the channel is closed.
     * 
     * You are holding mOutBufferLock.
     * 
     * @param size
     *            number of bytes desired
     * @return number of bytes allocated (may be less than requested)
     */
    private int waitForSendWindow(int size) {
        while (mOutWindowSize == 0) {
            synchronized (mLock) {
                if (mClosed || mEOFSent) {
                    return 0;
                }
            }

            try {
                mOutBufferLock.wait();
            } catch (InterruptedException x) {}
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

    private void feed(ChannelInputStream is, byte[] data) {
        synchronized (is.mBufferLock) {
            if (is.mBufferLen + data.length > is.mBuffer.length) {
                int newlen = 4 * is.mBuffer.length;
                while (is.mBufferLen + data.length > newlen) {
                    newlen *= 4;
                }
                byte[] newbuf = new byte[newlen];
                System.arraycopy(is.mBuffer, 0, newbuf, 0, is.mBufferLen);
                is.mBuffer = newbuf;
            }
            System.arraycopy(data, 0, is.mBuffer, is.mBufferLen, data.length);
            is.mBufferLen += data.length;
            is.mBufferLock.notifyAll();
        }

        if (mNotifyObject != null) {
            synchronized (mNotifyObject) {
                mNotifyObject.notifyAll();
            }
        }
    }

    private boolean handleWindowAdjust(Message m) {
        int nbytes = m.getInt();
        synchronized (mOutBufferLock) {
            mOutWindowSize += nbytes;
            mOutBufferLock.notifyAll();
        }
        return true;
    }

    private boolean handleData(Message m) {
        feed(mInStream, m.getByteString());
        return true;
    }

    private boolean handleExtendedData(Message m) {
        int code = m.getInt();
        byte[] data = m.getByteString();
        if (code != 1) {
            mLog.error("Unknown extended_data type " + code + "; discarding");
            return true;
        }

        if (mCombineStderr) {
            feed(mInStream, data);
        } else {
            feed(mStderrInStream, data);
        }

        return true;
    }

    private boolean handleEOF(Message m) {
        synchronized (mInStream.mBufferLock) {
            synchronized (mStderrInStream.mBufferLock) {
                synchronized (mLock) {
                    if (!mEOFReceived) {
                        mEOFReceived = true;
                        mInStream.mBufferLock.notifyAll();
                        mStderrInStream.mBufferLock.notifyAll();
                    }
                }
            }
        }
        mLog.debug("EOF received");
        return true;
    }

    private boolean handleClose(Message m) {
        close();
        synchronized (mLock) {
            mTransport.unlinkChannel(mChanID);
        }
        return true;
    }

    private boolean handleRequest(Message m) throws IOException {
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
        } else if (key.equals("pty-req")) {
            String term = m.getString();
            int width = m.getInt();
            int height = m.getInt();
            int pixelWidth = m.getInt();
            int pixelHeight = m.getInt();
            TerminalModes modes = TerminalModes.fromBytes(m.getByteString());
            if (mServer != null) {
                ok = mServer.checkChannelPTYRequest(this, term, width, height,
                        pixelWidth, pixelHeight, modes);
            } else {
                ok = false;
            }
        } else if (key.equals("shell")) {
            if (mServer != null) {
                ok = mServer.checkChannelShellRequest(this);
            } else {
                ok = false;
            }
        } else if (key.equals("exec")) {
            String command = m.getString();
            if (mServer != null) {
                ok = mServer.checkChannelExecRequest(this, command);
            } else {
                ok = false;
            }
        } else if (key.equals("subsystem")) {
            String name = m.getString();
            if (mServer != null) {
                ok = mServer.checkChannelSubsystemRequest(this, name);
            } else {
                ok = false;
            }
        } else if (key.equals("window-change")) {
            int width = m.getInt();
            int height = m.getInt();
            int pixelWidth = m.getInt();
            int pixelHeight = m.getInt();
            if (mServer != null) {
                ok = mServer.checkChannelWindowChangeRequest(this, width,
                        height, pixelWidth, pixelHeight);
            } else {
                ok = false;
            }
        } else {
            ok = handleCustomRequest(key, m);
        }

        if (wantReply) {
            Message mx = new Message();
            mx.putByte(ok ? MessageType.CHANNEL_SUCCESS
                    : MessageType.CHANNEL_FAILURE);
            mx.putInt(mRemoteChanID);
            mTransport.sendUserMessage(mx, DEFAULT_TIMEOUT);
        }
        return true;
    }

    private boolean handleSuccess(Message m) {
        mLog.debug("Secsh channel " + mChanID + " request ok");
        mEvent.set();
        return true;
    }

    private boolean handleFailure(Message m) {
        mLog.debug("Secsh channel " + mChanID + " request failed.");
        close();
        return true;
    }

    private int mChanID;
    private int mRemoteChanID;
    private String mKind;
    private List mParams;
    private boolean mActive;
    private boolean mClosed;
    private boolean mEOFReceived;
    private boolean mEOFSent;
    private boolean mCombineStderr;
    private Object mLock;
    private Event mEvent;
    private BaseTransport mTransport;
    private LogSink mLog;
    private ServerInterface mServer;
    private Object mNotifyObject;

    private int mInWindowThreshold; // bytes we must receive before we bother to
                                    // send a window update
    private int mInWindowSoFar;
    // package-scope for unit tests:
    /* package */int mOutWindowSize;
    /* package */int mOutMaxPacketSize;

    private ChannelInputStream mInStream;
    private ChannelInputStream mStderrInStream;
    private ChannelOutputStream mOutStream;
    private ChannelOutputStream mStderrOutStream;
    private Object mOutBufferLock;

    private int mExitStatus = -1;
    private Event mStatusEvent;
    private int mTimeout;

    // lower bound on the "max packet size" we'll allow from the server
    private static final int MIN_PACKET_SIZE = 1024;

    // default timeout for sending out-of-band messages like "close"
    private static final int DEFAULT_TIMEOUT = 100;
}
