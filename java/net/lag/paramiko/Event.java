/*
 * Created on May 11, 2005
 */

package net.lag.paramiko;

/**
 * A signal between threads, based on the python class of the same name.
 * 
 * <p>
 * An event is either clear (false) or set (true), and its state can be flipped
 * by any arbitrary thread.  Other thread(s) can wait for the event to be set.
 * Unlike condition variables (java's Object.notify and Object.wait), a set
 * event can be detected even if you weren't waiting at the exact moment that
 * it was set.
 * 
 * @author robey
 */
public final class Event
{
    /**
     * Create a new Event in the cleared state.
     */
    public
    Event ()
    {
        mSet = false;
        mLock = new Object();
    }

    /**
     * Create a new Event, pre-set to be either set or clear.
     * 
     * @param isSet true if the Event should initially be set; false if it
     *     should initially be clear
     */
    public
    Event (boolean isSet)
    {
        mSet = isSet;
        mLock = new Object();
    }
    
    /**
     * Clear the event flag.  Subsequently, threads calling {@link wait} will
     * block until {@link set} is called again.
     */
    public void
    clear ()
    {
        synchronized (mLock) {
            mSet = false;
        }
    }
    
    /**
     * Set the event flag.  All threads waiting on this event will be awakened.
     * Subsequently, threads that call {@link wait} will return immediately. 
     */
    public void
    set ()
    {
        synchronized (mLock) {
            mSet = true;
            mLock.notifyAll();
        }
    }
    
    /**
     * Return true if and only if the event is currently set.
     * 
     * @return true if the event is set; false if not
     */
    public boolean
    isSet ()
    {
        synchronized (mLock) {
            return mSet;
        }
    }
    
    /**
     * Block until the event flag becomes set.  If the event flag is already
     * set, return immediately.  Otherwise, block until another thread calls
     * {@link set}, or until the timeout occurs.
     * 
     * <p>The odd method name is to avoid conflict with a poorly-named java
     * builtin method.
     * 
     * @param timeout milliseconds to wait for the event to be set (0 = wait
     *     forever)
     * @throws InterruptedException if the thread was interrupted while waiting
     */
    public void
    waitFor (int timeout)
        throws InterruptedException
    {
        synchronized (mLock) {
            if (! mSet) {
                mLock.wait(timeout);
            }
            return;
        }
    }
    
    
    private boolean mSet;
    private Object mLock;
}
