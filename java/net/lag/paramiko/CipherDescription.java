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
 * Created on May 25, 2005
 */

package net.lag.paramiko;

/**
 * Description of ciphers we understand, what java calls them, and their
 * key/block size parameters.
 * 
 * @author robey
 */
/* package */ final class CipherDescription
{
    public CipherDescription (String j, int k, int b)
    {
        mJavaName = j;
        mKeySize = k;
        mBlockSize = b;
    }

    public String mJavaName;
    public int mKeySize;        // bytes
    public int mBlockSize;      // bytes
}
