import jpcap.NetworkInterface;


public class outerNetwork implements MessageAdapter {
	NetworkInterface nif;
	String UserName;
	String PassWord;
	
	MessageListener ml;
	
	public outerNetwork() {
		
	}

	@Override
	public void addMessageListener(MessageListener ml) {
		// TODO Auto-generated method stub
		this.ml = ml;
	}

}
