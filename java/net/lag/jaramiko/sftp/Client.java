package net.lag.jaramiko.sftp;

import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

import net.lag.jaramiko.Channel;
import net.lag.jaramiko.ClientTransport;
import net.lag.jaramiko.Message;
import net.lag.jaramiko.Transport;

public class Client extends Base {
	private int requestID;
	private int serverVersion;
	private static final int VERSION = 3;
	
	private static final int SFTP_FLAG_READ = 0x1;
	private static final int SFTP_FLAG_WRITE = 0x2;
	private static final int SFTP_FLAG_APPEND = 0x4;
	private static final int SFTP_FLAG_CREATE = 0x8;
	private static final int SFTP_FLAG_TRUNC = 0x10;
	private static final int SFTP_FLAG_EXCL = 0x20;

	
	public Client(Channel channel) throws IOException {
		super(channel);
		this.requestID = 1;
		this.serverVersion = sendVersion();
	}
	
	protected int sendVersion() throws IOException {
	   Message request = new Message();
	   request.putInt(VERSION);
       sendPacket(Command.Init, request);
       Message result = readPacket();
       if (result.getByte() != Command.Version.getBinaryCode()) {
    	   throw new RuntimeException("received unexpected respose to SFTP Init."); // FIXME.
       }
       return result.getInt();
	}
	
	public int getServerVersion() {
		return serverVersion;
	}

	public static Client fromTransport(ClientTransport transport) throws IOException {
		Channel channel = transport.openSession(5000); /* FIXME configurable timeout */
		if (channel == null)
			return null;
		channel.invokeSubsystem("sftp", 5000); /* FIXME configurable timeout */
		return new Client(channel);
	}
	
	public void close() {
		this.channel.close();
	}
	
	
	public List<String> listdir(String path) throws IOException {
		List<String> result = new ArrayList<String>();
		
		for (DirectoryEntry entry : listdirAttr(path)) {
			result.add(entry.getFilename());
		}
		return result;
	}
	
	public DirectoryEntry[] listdirAttr(String path) throws IOException {
		// path = adjustCWD(path);
		String handle = (String) (call(Command.Handle, new Class[] { String.class }, Command.OpenDir, path).get(0));
		
		try {
			return (DirectoryEntry[]) call(Command.Name, new Class[] { DirectoryEntry[].class }, Command.ReadDir, handle).get(0);
			
			// cmd ReadDir
			// cmd Close
		} finally {
			call(Command.Status, new Class[] { }, Command.Close, handle);
		}
	}

	
	// public open(String filename, mode, bufferSize)
	// => (handle :: <string>)
	// remove(path)
	// rename(oldPath, newPath)
	// mkdir(path, mode)
	// rmdir(path)
	// STAT(path)
	// LSTAT(path)
	// symlink(sourcePath, destinationPath)
	// XX chmod(path, mode)
	// XX chown(path, uid, gid)
	// setSTAT(path, STAT)
	// XX truncate(path, size)
	// readlink(path)
	// normalize(path)
	// XXX chdir(path)
	
	protected List<Object> call(Command expectedResultKind, Class[] expectedResultTypes, Command command, Object... args) throws IOException {
		Message message = new Message();
		message.putInt(this.requestID);
		
		for(int i = 0; i < args.length; ++i) {
			Object value = args[i];
			if (value instanceof Integer)
				message.putInt((Integer) value);
			else if (value instanceof Long)
				message.putInt64((Long) value);
			else if (value instanceof String)
				message.putString((String) value);
			else if (value instanceof byte[])
				message.putByteString((byte[]) value);
			else {
				try {
					value.getClass().getDeclaredMethod("toMessage", Message.class).invoke(value, message);
				} catch (IllegalArgumentException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					throw new RuntimeException("illegal argument"); // FIXME
				} catch (SecurityException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					throw new RuntimeException("security"); // FIXME
				} catch (IllegalAccessException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					throw new RuntimeException("illegal access"); // FIXME
				} catch (InvocationTargetException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					throw new RuntimeException("invocation target"); // FIXME
				} catch (NoSuchMethodException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					throw new RuntimeException("no such method"); // FIXME
				}
				//throw new RuntimeException(String.format("unknown argument type: %s", value.getClass())); // FIXME.
			}
		}
		
		++this.requestID;
		sendPacket(command, message);
		// FIXME async I/O.
		Message result = readPacket();
		
		int gotResultKind = result.getByte();
		int responseID = result.getInt();
		assert(responseID == this.requestID - 1);
		
		if (gotResultKind == Command.Status.getBinaryCode()) {
			parseStatus(result);
			return null;
		}

		if (gotResultKind != expectedResultKind.getBinaryCode()) {
			throw new RuntimeException("received unknown response.");
		}
		List<Object> resultList = new ArrayList<Object>();
		
		for (Class kind : expectedResultTypes) {
			if (String.class.isAssignableFrom(kind))
				resultList.add(result.getString());
			else if (Integer.class.isAssignableFrom(kind))
				resultList.add(result.getInt());
			else if (kind.isArray()) { // Array.class.isAssignableFrom(kind)) {
				Class<?> componentType = kind.getComponentType();
				
				if (byte.class.isAssignableFrom(componentType)) {
					byte[] array = result.getByteString();
					resultList.add(array);
				} else {
					int count = result.getInt();
					
					Object array = Array.newInstance(componentType, count);
					for (int i = 0; i < count; ++i) {
						Object element;
						try {
							element = componentType.getDeclaredMethod("fromMessage", Message.class).invoke(null, result);
						} catch (IllegalArgumentException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
							throw new RuntimeException("illegal argument"); // FIXME
						} catch (SecurityException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
							throw new RuntimeException("security"); // FIXME
						} catch (IllegalAccessException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
							throw new RuntimeException("illegal access"); // FIXME
						} catch (InvocationTargetException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
							throw new RuntimeException("invocation"); // FIXME
						} catch (NoSuchMethodException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
							throw new RuntimeException("no such method"); // FIXME
						}
						Array.set(array, i, element);
					}
					resultList.add(array);
				}
			} else
				throw new RuntimeException("unknown type " + kind); // FIXME.
		}
		
		return resultList;
	}

	/** parses a Status message and throws the corresponding exception, if any.
	 * Will only return without throwing exception if it was #OK.
	 * assumes that the type byte has already been read. 
	 * @throws IOException */
	protected void parseStatus(Message message) throws IOException {
        int code = message.getInt();
        String text = message.getString();
        
        if (code == Status.OK.getBinaryCode())
            return;
        else if (code == Status.EOF.getBinaryCode())
        	throw new EOFException(text);
        else if (code == Status.NoSuchFile.getBinaryCode()) {
            // clever idea from john a. meinel: map the error codes to errno
            throw new FileNotFoundException(text);
        } else if (code == Status.PermissionDenied.getBinaryCode())  
            throw new IOException(text); // FIXME
        else
        	throw new IOException(text);
	}

	// TODO: "File" abstraction?
	public java.io.InputStream openInputStream(final String path/*, Attributes attributes*/) throws IOException {
		final Attributes attributes = new Attributes();
		final int mode = SFTP_FLAG_READ; // FIXME other flags.
		final int MAX_REQUESTED_READ = 32768;
		
		final String handle = (String) (call(Command.Handle, new Class[] { String.class }, Command.Open, path, mode, attributes).get(0));
		return new java.io.InputStream() {
			private boolean autoClose = true;
			private long offset = 0;
			
			@Override
			public int read() throws IOException {
				byte[] result = read(offset, 1);
				if (result.length == 0)
					return -1;
				++offset;
				return result[0];
			}
			
			@Override
			public void close() throws IOException {
				if (autoClose) {
					call(Command.Status, null, Command.Close, handle);
					 autoClose = false;
				}
				// TODO Auto-generated method stub
				super.close();
			}
			
			protected byte[] read(long position, int size) throws IOException {
				if (size > MAX_REQUESTED_READ)
					size = MAX_REQUESTED_READ;
				
				/*if (size == 0) {
					return new byte[0];
				}*/
					
		        //t, msg = self.sftp._request(CMD_READ, self.handle, long(self._realpos), int(size))
				byte[] data = (byte[]) call(Command.Data, new Class[] { byte[].class }, Command.Read, handle, position, size).get(0);
				
				return data;
			}
			
			/*protected void write(long position, int size, byte[] data) throws IOException {
				call(Command.Status, null, Command.Write, handle, position, data).get(0);
			}*/
			
			@Override
		    public int read(byte b[], int b_off, int len) throws IOException {
		    	if (b == null) {
		    	    throw new NullPointerException();
		    	} else if (b_off < 0 || len < 0 || len > b.length - b_off) {
		    	    throw new IndexOutOfBoundsException();
		    	} else if (len == 0) {
		    	    return 0;
		    	}

		    	try {
		    		byte[] data = read(offset, len);
		    	
			    	/*if (data.length == 0)
			    		return -1;*/
			    	for(int i = 0; i < data.length; ++i)
			    		b[b_off + i] = data[i];
			    	
					offset += data.length;
			    	
			    	return data.length;
		    	} catch (EOFException exception) {
		    		return -1;
		    	}
		    }
		};
	}
}
