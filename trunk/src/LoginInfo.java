import java.net.InetAddress;
import java.net.UnknownHostException;

import jpcap.NetworkInterface;


final class LoginInfo {
	public NetworkInterface nif;
	public byte[] src_mac;
	public byte[] dst_mac;
	public String UserName;
	public String PassWord;
	public InetAddress ServerAddress;
	public InetAddress host_dnsp;
	public InetAddress host_dnss;
	public InetAddress dhcp;
	
	LoginInfo() {
		try {
			ServerAddress = InetAddress.getByName("10.5.2.3");
			
			host_dnsp = InetAddress.getByName("211.64.192.1");
			host_dnss = InetAddress.getByName("8.8.4.4");
			
			dhcp = InetAddress.getByName("222.195.240.8");
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
}
