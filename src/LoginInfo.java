import java.net.InetAddress;
import java.net.UnknownHostException;

import jpcap.NetworkInterface;



final class LoginInfo {
	public NetworkInterface nif = null;
	public byte[] src_mac = null;
	public byte[] dst_mac = null;
	public String UserName = null;
	public String PassWord = null;
	public InetAddress ServerAddress = null;
	public InetAddress host_dnsp = null;
	public InetAddress host_dnss = null;
	public InetAddress dhcp = null;
	public int port = 0xF000; // 默认端口 61440;;
	public String os= null;
	public String dhcpScript = null;
	
	LoginInfo() {
		try {
			ServerAddress = InetAddress.getByName("1.1.1.1"); //202.1.1.1
			host_dnsp = InetAddress.getByName("211.64.192.1");
			host_dnss = InetAddress.getByName("8.8.4.4");

			dhcp = InetAddress.getByName("222.195.240.8");
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
