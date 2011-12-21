import java.io.IOException;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;

public class IntranetNetwork implements MessageAdapter, PacketReceiver {
	enum State {
		START, Identity, Challenge, LOGOFF
	};

	public State state = State.START;

	LoginInfo logif;

	JpcapCaptor pc;
	JpcapSender ps;

	MessageListener ml;
	long startTime = System.currentTimeMillis();

	public IntranetNetwork(LoginInfo logif) {
		// TODO Auto-generated constructor stub
		this.logif = logif;

		try {
			pc = JpcapCaptor.openDevice(logif.nif, 120, true, 200);

			pc.setFilter("ether dst 01:80:c2:00:00:03 and ether proto 0x888e",
					false);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		pc.setNonBlockingMode(false);
		ps = pc.getJpcapSenderInstance();
	}

	@SuppressWarnings("deprecation")
	public void Start() {
		int RetryTimes = 0;

		_802dot1XPacket start = new _802dot1XPacket(logif.src_mac,
				_802dot1XPacket.EAPOL_TYPE_START);

		ps.sendPacket(start);
		ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE, "寻找服务器...\n"));
		startTime = System.currentTimeMillis();
		while (pc.dispatchPacket(0, (PacketReceiver) this) >= 0) {
			if (System.currentTimeMillis() - startTime > 5000) {
				switch (state) {
				case START:
					if (++RetryTimes > 3) {
						ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
								"登陆超时，建议插拔网线后重试\n"));
						return;
					}
					_802dot1XPacket reStart = new _802dot1XPacket(
							logif.src_mac, _802dot1XPacket.EAPOL_TYPE_START);
					ps.sendPacket(reStart);
					startTime = System.currentTimeMillis();

					ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
							"寻找服务器超时，重试" + RetryTimes + "\n"));
					break;
				case Identity:

					break;
				case Challenge:
					ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
							"密码验证超时，可能交换机误检测为APR攻击，请使用系统修改MAC重试\n"));
					return;
				default:
					startTime = System.currentTimeMillis();
					break;
				}
			}
		}
		// System.out.println(ret);
		// pc.loopPacket(-1, (PacketReceiver) this);// 循环
		pc.close();
	}

	public void receivePacket(Packet p) {
		// System.out.println("receivePacket");

		_802dot1XPacket tmp = new _802dot1XPacket(p);

		switch (tmp.getEAPOLType()) {
		case _802dot1XPacket.EAPOL_TYPE_LOGOFF:
			// ml.ReciveMessage(new Message(Message.ERROR, "服务器强制下线！\n"));
			break;
		case _802dot1XPacket.EAPOL_TYPE_EAPPACKET:
			switch (tmp.getEAPCode()) {
			case _802dot1XPacket.EAP_CODE_REQUEST:

				switch (tmp.getEAPType()) {
				case _802dot1XPacket.EAP_REQUEST_IDENTITY:
					tmp.ConvertToIdentityResponse(logif.UserName, logif.src_mac);
					ps.sendPacket(tmp);
					state = State.Identity;
					startTime = System.currentTimeMillis();
					ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
							"发送用户名\n"));
					break;
				case _802dot1XPacket.EAP_REQUEST_NOTIFICATION:
					ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
							"notic"));
					break;
				case _802dot1XPacket.EAP_REQUEST_MD5_CHALLENGE:
					tmp.ConvertToMD5ChallengeResponse(logif.UserName,
							logif.PassWord, logif.src_mac);
					ps.sendPacket(tmp);
					state = State.Challenge;
					startTime = System.currentTimeMillis();
					ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
							"发送密码\n"));
					break;
				}
				break;
			case _802dot1XPacket.EAP_CODE_FAILURE:
				ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
						"内网登陆失败!请检查用户名、密码、MAC是否正确,且没有他人正在使用此账号!\n请等待1分钟或插拔网线后重试\n"));
				pc.breakLoop();
				break;
			case _802dot1XPacket.EAP_CODE_SUCCESS:
				ml.ReciveMessage(new Message(Message.Msgtype.INNERSUCCESS,
						"内网登陆成功!\n"));
				// 增加断线重拨 ...

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
				_802dot1XPacket.EAPOL_TYPE_LOGOFF);

		ps.sendPacket(start);
		ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE, "内网注销成功!\n"));
		return false;
	}

	public void run() {
		Start();
	}

	@Override
	public void addMessageListener(MessageListener ml) {
		// TODO Auto-generated method stub
		this.ml = ml;
	}
}
