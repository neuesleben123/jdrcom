
public class Message{
	int type;
	public static final int ERROR = 0;
	public static final int SUCCESS = 1;
	public static final int MESSAGE = 2;
	
	String msg;
	
	public Message() {
		
	}
	public Message (int type,String msg) {
		this.type = type;
		this.msg = msg;
	}
}
