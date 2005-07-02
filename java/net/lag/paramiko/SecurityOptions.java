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
 * Created on Jul 1, 2005
 */

package net.lag.paramiko;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;


/**
 * Simple object containing the security preferences of an SSH {@link Transport}.
 * These are lists of acceptable ciphers, digests, key types, and key exchange
 * algorithms, listed in order of preference.
 * 
 * <p>Changing the contents and/or order of these fields affects the
 * underlying {@link Transport}, but only if you change them before starting
 * the session.  If you try to add an algorithm that paramiko doesn't
 * recognize, an IllegalArgumentException will be thrown.
 * 
 * @author robey
 */
public final class SecurityOptions
{
    /* package */
    SecurityOptions (String[] knownCiphers, String[] knownMacs, String[] knownKeys, String[] knownKex)
    {
        mKnownCiphers = knownCiphers;
        mKnownMacs = knownMacs;
        mKnownKeys = knownKeys;
        mKnownKex = knownKex;
        
        mCiphers = new ArrayList(Arrays.asList(knownCiphers));
        mMacs = new ArrayList(Arrays.asList(knownMacs));
        mKeys = new ArrayList(Arrays.asList(knownKeys));
        mKex = new ArrayList(Arrays.asList(knownKex));
    }
    
    public void
    setCiphers (List ciphers)
    {
        setList(mCiphers, ciphers, mKnownCiphers);
    }
    
    public void
    setMacs (List macs)
    {
        setList(mMacs, macs, mKnownMacs);
    }
    
    public void
    setKeys (List keys)
    {
        setList(mKeys, keys, mKnownKeys);
    }
    
    public void
    setKex (List kex)
    {
        setList(mKex, kex, mKnownKex);
    }
    
    public List
    getCiphers ()
    {
        return new ArrayList(mCiphers);
    }
    
    public List
    getMacs ()
    {
        return new ArrayList(mMacs);
    }
    
    public List
    getKeys ()
    {
        return new ArrayList(mKeys);
    }
    
    public List
    getKex ()
    {
        return new ArrayList(mKex);
    }
    
    
    private void
    setList (List mine, List theirs, String[] valid)
    {
        mine.clear();
        for (Iterator i = theirs.iterator(); i.hasNext(); ) {
            String x = (String) i.next();
            if (! Arrays.asList(valid).contains(x)) {
                throw new IllegalArgumentException();
            }
            mine.add(x);
        }
    }
    
    private String[] mKnownCiphers;
    private String[] mKnownMacs;
    private String[] mKnownKeys;
    private String[] mKnownKex;
    
    private List mCiphers;
    private List mMacs;
    private List mKeys;
    private List mKex;
    

}
