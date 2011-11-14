import java.io.IOException;
import java.util.Properties;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;

public class innerNetwork implements MessageAdapter, PacketReceiver {
	/*NetworkInterface nif;
	byte[] src_mac;
	byte[] dst_mac;
	String UserName;
	String PassWord;
*/
	LoginInfo logif;
	
	JpcapCaptor pc;
	JpcapSender ps;

	MessageListener ml;

	public innerNetwork(LoginInfo logif) {
		// TODO Auto-generated constructor stub
		this.logif = logif;

		try {
			pc = JpcapCaptor.openDevice(logif.nif, 120, true, 250);

			pc.setFilter("ether dst 01:80:c2:00:00:03 and ether proto 0x888e",
					false);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		pc.setNonBlockingMode(false);

		ps = pc.getJpcapSenderInstance();
	}

	public void login() {

		_802dot1XPacket start = new _802dot1XPacket(logif.src_mac,
				_802dot1XPacket.EAPOL_TYPE_START);

		ps.sendPacket(start);
		ml.ReciveMessage(new Message(Message.MESSAGE, "寻找服务器..."));

		pc.loopPacket(-1, (PacketReceiver) this);// 循环
		pc.close();
	}

	public void receivePacket(Packet p) {
		_802dot1XPacket tmp = new _802dot1XPacket(p);

		switch (tmp.getEAPOLType()) {
		case _802dot1XPacket.EAPOL_TYPE_LOGOFF:
			ml.ReciveMessage(new Message(Message.ERROR, "服务器强制下线！"));
			break;
		case _802dot1XPacket.EAPOL_TYPE_EAPPACKET:
			switch (tmp.getEAPCode()) {
			case _802dot1XPacket.EAP_CODE_REQUEST:

				switch (tmp.getEAPType()) {
				case _802dot1XPacket.EAP_REQUEST_IDENTITY:
					tmp.ConvertToIdentityResponse(logif.UserName, logif.src_mac);
					ps.sendPacket(tmp);
					ml.ReciveMessage(new Message(Message.MESSAGE, "发送用户名"));
					break;
				case _802dot1XPacket.EAP_REQUEST_NOTIFICATION:
					ml.ReciveMessage(new Message(Message.MESSAGE, "notic"));
					break;
				case _802dot1XPacket.EAP_REQUEST_MD5_CHALLENGE:
					tmp.ConvertToMD5ChallengeResponse(logif.UserName, logif.PassWord,
							logif.src_mac);
					ps.sendPacket(tmp);
					ml.ReciveMessage(new Message(Message.MESSAGE, "发送密码"));
					break;
				}
				break;
			case _802dot1XPacket.EAP_CODE_FAILURE:
				ml.ReciveMessage(new Message(Message.ERROR,
						"内网登陆失败!请检查用户名、密码是否正确"));
				pc.breakLoop();
				break;
			case _802dot1XPacket.EAP_CODE_SUCCESS:
				ml.ReciveMessage(new Message(Message.SUCCESS, "内网登陆成功!"));
				//增加断线重拨 ...
				
				pc.breakLoop();
				break;
			}
			break;
		}
		// ml.ReciveMessage(new Message(Message.ERROR, p.toString()));
	}

	// /////////////////////////////////////////////////////////////////

	public boolean logoff() {
		_802dot1XPacket start = new _802dot1XPacket(logif.src_mac,
				_802dot1XPacket.EAPOL_TYPE_START);

		ps.sendPacket(start);
		ml.ReciveMessage(new Message(Message.MESSAGE, "寻找服务器..."));
		return false;
	}

	@Override
	public void addMessageListener(MessageListener ml) {
		// TODO Auto-generated method stub
		this.ml = ml;
	}
}
