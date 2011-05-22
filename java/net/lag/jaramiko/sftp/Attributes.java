package net.lag.jaramiko.sftp;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import net.lag.jaramiko.Message;

public class Attributes implements Comparable<Attributes> {
	private int flags;
    private Long st_size;
    private Integer st_uid;
    private Integer st_gid;
    private Integer st_mode;
    private Integer st_atime;
    private Integer st_mtime;
    private String filename; // optional

	private Map<String, String> attr = new HashMap<String, String>();

    static final int FLAG_SIZE = 1;
    static final int FLAG_UIDGID = 2;
    static final int FLAG_PERMISSIONS = 4;
    static final int FLAG_AMTIME = 8;
    static final int FLAG_EXTENDED = 0x80000000;
    
    public static Attributes fromMessage(Message message) {
    	Attributes attributes = new Attributes();
    	attributes.flags = message.getInt();
        if ((attributes.flags & FLAG_SIZE) != 0)
        	attributes.st_size = message.getInt64();
        if ((attributes.flags & FLAG_UIDGID) != 0) {
        	attributes.st_uid = message.getInt();
        	attributes.st_gid = message.getInt();
        }
        if ((attributes.flags & FLAG_PERMISSIONS) != 0)
        	attributes.st_mode = message.getInt();
        if ((attributes.flags & FLAG_AMTIME) != 0) {
        	attributes.st_atime = message.getInt();
        	attributes.st_mtime = message.getInt();
        }
        if ((attributes.flags & FLAG_EXTENDED) != 0) {
            int count = message.getInt();
            for (int i = 0; i < count; ++i) {
            	String key = message.getString();
            	// FIXME order.
            	attributes.attr.put(key, message.getString());
            }
        }
        return attributes;
    }

	
    
	public Long getSt_size() {
		return st_size;
	}



	public void setSt_size(Long st_size) {
		this.st_size = st_size;
		if (st_size != null)
			flags |= FLAG_SIZE;
		else
			flags &= ~FLAG_SIZE;
	}



	public Integer getSt_uid() {
		return st_uid;
	}



	public void setSt_uid(Integer st_uid) {
		this.st_uid = st_uid;
		if (st_uid != null && this.st_gid != null)
			flags |= FLAG_UIDGID;
		else
			flags &= ~FLAG_UIDGID;
	}



	public Integer getSt_gid() {
		return st_gid;
	}



	public void setSt_gid(Integer st_gid) {
		this.st_gid = st_gid;
		if (st_uid != null && this.st_uid != null)
			flags |= FLAG_UIDGID;
		else
			flags &= ~FLAG_UIDGID;
	}



	public Integer getSt_mode() {
		return st_mode;
	}



	public void setSt_mode(Integer st_mode) {
		this.st_mode = st_mode;
		if (st_mode != null)
			flags |= FLAG_PERMISSIONS;
		else
			flags &= ~FLAG_PERMISSIONS;
	}



	public Integer getSt_atime() {
		return st_atime;
	}



	public void setSt_atime(Integer st_atime) {
		this.st_atime = st_atime;
		if (st_atime != null && this.st_mtime != null)
			flags |= FLAG_AMTIME;
		else
			flags &= ~FLAG_AMTIME;
	}



	public Integer getSt_mtime() {
		return st_mtime;
	}



	public void setSt_mtime(Integer st_mtime) {
		this.st_mtime = st_mtime;
		if (st_atime != null && st_mtime != null)
			flags |= FLAG_AMTIME;
		else
			flags &= ~FLAG_AMTIME;
	}


	public void toMessage(Message message) {
        this.flags = 0;
        if (this.st_size != null)
        	this.flags |= FLAG_SIZE;
        if (this.st_uid != null && this.st_gid != null)
        	this.flags |= FLAG_UIDGID;
        if (this.st_mode != null)
        	this.flags |= FLAG_PERMISSIONS;
        if (this.st_atime != null && this.st_mtime != null)
        	this.flags |= FLAG_AMTIME;
        if (!this.attr.isEmpty())
        	this.flags |= FLAG_EXTENDED;
        message.putInt(this.flags);
        if ((this.flags & FLAG_SIZE) != 0)
            message.putInt64(this.st_size);
        if ((this.flags & FLAG_UIDGID) != 0) {
        	message.putInt(this.st_uid);
            message.putInt(this.st_gid);
        }
        if ((this.flags & FLAG_PERMISSIONS) != 0)
            message.putInt(this.st_mode);
        if ((this.flags & FLAG_AMTIME) != 0) {
            // throw away any fractional seconds
        	message.putInt((int) this.st_atime);
        	message.putInt((int) this.st_mtime);
        }
        if ((this.flags & FLAG_EXTENDED) != 0) {
        	message.putInt(this.attr.size());
            for (Entry<String, String> entry : this.attr.entrySet()) {
            	message.putString(entry.getKey());
            	message.putString(entry.getValue());
            }
        }
        return;
	}
    public String getFilename() {
		return filename;
	}

	public void setFilename(String filename) {
		this.filename = filename;
	}
	
	private final int S_IFDIR = 0x4000;
	private final int S_IFBLK = 0x6000;
	private final int S_IFLNK = 0xA000;
	private final int S_IFCHR = 0x2000;
	private final int S_IFREG = 0x8000;
	private final int S_IFSOCK = 0xC000;
	private final int S_IFIFO = 0x1000;
	private final int S_ISVTX = 0x200;
	private final int S_IFMT = 0xF000;
	
	public int getFormat() {
		return (st_mode != null) ? (st_mode & S_IFMT) : 0;
	}
	
	public boolean isDirectory() {
		return (getFormat() == S_IFDIR);
	}
	
	public boolean isBlockDevice() {
		return (getFormat() == S_IFBLK);
	}

	public boolean isSymbolicLink() {
		return (getFormat() == S_IFLNK);
	}

	public boolean isCharacterDevice() {
		return (getFormat() == S_IFCHR);
	}

	public boolean isSocket() {
		return (getFormat() == S_IFSOCK);
	}

	public boolean isRegular() {
		return (getFormat() == S_IFREG);
	}
	
	public boolean isPipe() {
		return (getFormat() == S_IFIFO);
	}
	
	public boolean isSticky() {
		return (getFormat() & S_ISVTX) != 0;
	}

	@Override
	public int compareTo(Attributes o) {
		int result = (st_size == o.st_size) ? 0 : st_size.compareTo(o.st_size);
		if (result == 0) {
			result = (st_uid == o.st_uid) ? 0 : st_uid.compareTo(o.st_uid);
			if (result == 0) {
				result = (st_gid == o.st_gid) ? 0 : st_gid.compareTo(o.st_gid);
				if (result == 0) {
					result = (st_mode == o.st_mode) ? 0 : st_mode.compareTo(o.st_mode);
					if (result == 0) {
						result = (st_atime == o.st_atime) ? 0 : st_atime.compareTo(o.st_atime);
						if (result == 0) {
							result = (st_mtime == o.st_mtime) ? 0 : st_mtime.compareTo(o.st_mtime);
						}
					}
				}
			}
		}
	    // filename; // optional
		return result;
	}
	
}
