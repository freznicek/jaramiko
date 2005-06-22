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

/**
 * @author robey
 */
public class Channel
{
    /* package */
    Channel (int chanid)
    {
        mChanID = chanid;
        mActive = false;
        mClosed = false;
        mLock = new Object();
        // ...
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
        if (mClosed) {
            return;
        }
        
        synchronized (mLock) {
            setClosed();
            mTransport.unlinkChannel(mChanID);
        }

    }
    
    // you are holding the lock.
    private void
    setClosed ()
    {
        mClosed = true;
        // FIXME:
//            self.in_buffer_cv.notifyAll()
  //          self.in_stderr_buffer_cv.notifyAll()
    //        self.out_buffer_cv.notifyAll()
    }

    
    private int mChanID;
    private int mRemoteChanID;
    private boolean mActive;
    private boolean mClosed;
    private Object mLock;
    private TransportInterface mTransport;
    private LogSink mLog;
    
    private int mInWindowSize;
    private int mInMaxPacketSize;
    private int mInWindowThreshold;     // bytes we must receive before we bother to send a window update
    private int mInWindowSoFar;
    
    private int mOutWindowSize;
    private int mOutMaxPacketSize;
 
    // lower bound on the "max packet size" we'll allow from the server
    private static final int MIN_PACKET_SIZE = 1024;
}
