public class Message {
	public enum Msgtype {
		ERROR, INNERSUCCESS, MESSAGE,OUTTERSUCCESS
	};

	Msgtype type=Msgtype.MESSAGE;
	String msg=null;

	public Message() {

	}

	public Message(Msgtype type, String msg) {
		this.type = type;
		this.msg = msg;
	}
}
