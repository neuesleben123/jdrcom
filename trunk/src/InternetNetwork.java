import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.util.Timer;
import java.util.TimerTask;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class InternetNetwork implements MessageAdapter, Runnable {

	enum State {
		START, LOGIN, ONLINE, STOP, LOGOFF
	};

	public State state = State.START;

	private LoginInfo logif = null;
	private MessageListener ml = null;

	private byte[] service_identifier = null;
	private byte[] login_a_md5 = null;
	private byte[] auth_info = new byte[16];

	Timer alive = new Timer(false);

	private DatagramSocket socket = null;
	private byte recv_data[] = new byte[256];
	private byte send_data[] = null;

	private int onlineTime = 0;
	private int totalTime = 0;
	private int balance = 0;
	private int totalFlux = 0;
	private int timeBalance = 0;
	private int fluxBalance = 0;

	public InternetNetwork(LoginInfo logif) throws Exception {
		this.logif = logif;

		for (NetworkInterface n : JpcapCaptor.getDeviceList()) {
			if (n.name.equals(logif.nif.name)) {
				logif.nif = n;
				try {
					// socket = new DatagramSocket(logif.port,
					// n.addresses[0].address);
					socket = new DatagramSocket(logif.port);
					socket.setSoTimeout(3000);
				} catch (SocketException e) {
					// TODO Auto-generated catch block
					throw new Exception(e);
				}
				break;
			}
		}

	}

	public boolean Start() {
		boolean ret = true;
		int RetryTimes = 0;

		DatagramPacket recv_packet = new DatagramPacket(recv_data,
				recv_data.length);

		labwhile: while (true) {

			switch (state) {
			case START:
				state = State.LOGIN;
				RetryTimes = 0;
				if (!Send_Start_Request()) {
					ret = false;
					break labwhile;
				}
				break;
			case STOP:
				alive.cancel();
				Send_Alive();
				state = State.LOGOFF;
				RetryTimes = 0;
				Send_Start_Request();
				break;
			}

			try {
				socket.receive(recv_packet);
			} catch (UnknownHostException e) {
				// e.printStackTrace();
				ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
						"获取本机IP失败！\n"));
				ret = false;
				break labwhile;
			} catch (SocketTimeoutException e) {
				switch (state) {
				case LOGIN:
					// TODO:搜索第二服务器
					RetryTimes++;
					if (RetryTimes < 4) {
						ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
								"服务器响应超时！重试" + RetryTimes + "\n"));
						if (RetryTimes > 1)
							try {
								logif.ServerAddress = InetAddress
										.getByName("202.1.1.1");
								ml.ReciveMessage(new Message(
										Message.Msgtype.MESSAGE, "使用探测IP方式2\n"));
							} catch (UnknownHostException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}

					} else {
						ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
								"登陆超时，是否指定了错误的服务器IP？\n"));
						ret = false;
						break labwhile;
					}
					break;
				case LOGOFF:
					RetryTimes++;
					if (RetryTimes < 4) {
						ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
								"注销超时，服务器响应超时！重试" + RetryTimes + "\n"));
						break;
					} else {
						ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
								"注销超时，请指定下线参数重新运行\n"));
						ret = false;
						break labwhile;
					}
				default:
					continue;
				}
			} catch (IOException e) {
				e.printStackTrace();
				ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
						"与服务器通讯时发生错误\n"));
			}

			switch (recv_data[0]) {
			case 0x02:
				logif.ServerAddress = recv_packet.getAddress(); // 自动获取服务器IP
				ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
						"自动探测到服务器IP" + logif.ServerAddress.toString() + "\n"));
				Handle_Start_Response(recv_data);
				if (state == State.LOGIN)
					Send_Login_Auth(recv_data);
				else
					Send_Logout_Auth(recv_data);
				break;
			case 0x04:
				if (state == State.LOGIN)
					Handle_Success(recv_data);
				else {
					ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
							"注销成功！\n"));
					Output_Infomation();
					ret = true;
					break labwhile;
				}
				break;
			case 0x05:
				Handle_Failure(recv_data);
				ret = false;
				break labwhile;
			case 0x07:
				switch (recv_data[5]) {
				case 0x00: // response for alive
					Handle_Alive_Response(recv_data);
					break;
				}
				break;
			case 0x4d:
				switch (recv_data[1]) {
				case 0x25:
					ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
							"\n费用超支，不能上网！\n"));
					ret = false;
					break labwhile;
				case 0x38:
					String msg = null;
					try {
						msg = new String(recv_data, 4,
								recv_packet.getLength() - 4, "GBK");
					} catch (UnsupportedEncodingException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
							"\n服务器消息：" + msg + "\n"));
					break;
				}
				break;
			default:
				// for (byte b : recv_data) {
				// System.out.print(b);
				// }
				ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE,
						"\n收到未知包，忽略\n"));
				break;
			}
		}
		return ret;
	}

	private boolean Handle_New_Password(byte[] recv_data) {

		return true;
	}

	private boolean Handle_Start_Response(byte[] recv_data) {
		// 检查
		if (recv_data[0] != 0x02) {
			ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
					"登录失败。发出连接请求，服务器响应错误！\n"));
			return false;
		}

		ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE, "收到同意连接\n"));
		service_identifier = new byte[4];
		System.arraycopy(recv_data, 4, service_identifier, 0, 4);

		/*
		 * service_identifier = new byte[] { (byte) 0x8a, 0x5f, 0x01, 0x00 };
		 */
		return true;
	}

	private boolean Handle_Success(byte[] recv_data) {
		ml.ReciveMessage(new Message(Message.Msgtype.OUTTERSUCCESS,
				"登录成功！\n开始发送心跳包...\n"));
		state = State.ONLINE;
		System.arraycopy(recv_data, 23, auth_info, 0, 16);

		totalTime = byteArrayToInt(recv_data, 5);
		totalFlux = byteArrayToInt(recv_data, 9);
		balance = byteArrayToInt(recv_data, 13);

		// start alive timer
		alive.schedule(new TimerTask() {
			public void run() {
				Send_Alive();
			}
		}, 0, 20 * 1000);
		return true;
	}

	public void Output_Infomation() {
		String info = null;
		info = String.format("\n*****************************\n"
				+ "本月在线时间:\t%d分钟\n" + "本月总流量:\t%f MB\n" + "余额:\t\t%f元\n"
				+ "本次可用时间:\t%s\n" + "本次可用流量:\t%s\n" + "本次在线时间:\t%d分%d秒\n"
				+ "*****************************\n", totalTime,
				(totalFlux & 0x0FFFFFFFF) / 1024.0,
				(balance & 0x0FFFFFFFF) / 100.0, timeBalance == -1 ? "无限制"
						: (timeBalance & 0x0FFFFFFFF) / 60.0 + "分钟",
				fluxBalance == -1 ? "无限制" : (fluxBalance & 0x0FFFFFFFF)
						/ 1024.0 + " MB", (onlineTime & 0x0FFFFFFFF) / 60,
				(onlineTime & 0x0FFFFFFFF) % 60);
		ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE, info));
	}

	private void Handle_Alive_Response(byte[] recv_data) {
		onlineTime = byteArrayToInt(recv_data, 32);
		// totalTime = byteArrayToInt(recv_data, 44);
		// totalFlux = byteArrayToInt(recv_data, 48);
		// balance = byteArrayToInt(recv_data, 52);
		// balance /= 100;

		timeBalance = byteArrayToInt(recv_data, 56);
		fluxBalance = byteArrayToInt(recv_data, 60);
	}

	private void Handle_Failure(byte[] recv_data) {
		ml.ReciveMessage(new Message(Message.Msgtype.ERROR, "登陆失败:\n"));
		if (recv_data[4] == 0x01) {
			// offset: 5: in use IP 4byte;
			// offset: 9: in use MAC 6 byte;
			String IP = String.format("IP:%d.%d.%d.%d ", recv_data[5],
					recv_data[6], recv_data[7], recv_data[8]);
			String MAC = String.format("MAC:%02X-%02X-%02X-%02X-%02X-%02X ",
					recv_data[9], recv_data[10], recv_data[11], recv_data[12],
					recv_data[13], recv_data[14]);

			ml.ReciveMessage(new Message(Message.Msgtype.ERROR, "改账号已在" + IP
					+ MAC + "上登录！\n"));
		}
		// Username or password error!
		else if (recv_data[4] == 0x03) {
			ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
					"用户名或密码不对，请重新输入！\n"));
		}
		// // exceed the balance.....
		// else if (recv_data[4] == 0x04) {
		// ml.ReciveMessage(new Message(Message.Msgtype.ERROR, "费用超支，不能上网！"));
		// }
		// Wrong IP -- Account not match 802.1X Account
		else if (recv_data[4] == 0x07) {
			ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
					"与内网绑定MAC不匹配！(可指定MAC重试)\n"));
		}
		// Wrong MAC
		else if (recv_data[4] == 0x0b) {
			String MAC = String.format("%02X-%02X-%02X-%02X-%02X-%02X ",
					recv_data[5], recv_data[6], recv_data[7], recv_data[8],
					recv_data[9], recv_data[10]);
			ml.ReciveMessage(new Message(Message.Msgtype.ERROR, "登陆MAC不匹配！应为:"
					+ MAC + " 请使用-s指定此MAC重试\n"));
		}
		// other 0x05 error
		else {
			ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
					"登录失败。发出登录认证包，可能服务器没有通过验证，请查看是否需要升级客户端程序!\n"));
		}
	}

	private boolean Send_Start_Request() {

		// ////////////////////////////////////////////////////////////////////////
		// 发送第一个包
		// ////////////////////////////////////////////////////////////////////////
		send_data = new byte[20];

		send_data[0] = 0x01; // type
		send_data[1] = 0x00; // 拨号次数（包括802.1X）
		// challenge ?
		send_data[2] = 0x00;
		send_data[3] = 0x00;

		send_data[4] = 0x09; // 固定 ，版本？

		DatagramPacket send_packet = new DatagramPacket(send_data,
				send_data.length, logif.ServerAddress, logif.port);

		ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE, "\n发送连接请求...\n"));
		try {
			socket.send(send_packet);
		} catch (IOException e) {
			e.printStackTrace();
			ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
					"发送Start Request失败！("
							+ send_packet.getSocketAddress().toString() + ")\n"));
			return false;
		}
		return true;
	}

	private boolean Send_New_Password(byte[] recv_data) {

		return true;
	}

	public boolean Send_Alive() {

		send_data = new byte[20]; // type

		send_data[0] = (byte) 0xff;

		System.arraycopy(login_a_md5, 0, send_data, 1, 16);

		send_data = arraycat(send_data, auth_info);

		// try {
		// Process process = null;
		// if (logif.os.equals("windows"))
		// process = Runtime.getRuntime().exec(
		// "cmd /c net statistics workstation");
		// process.getInputStream().toString();
		// } catch (IOException e1) {
		// // TODO Auto-generated catch block
		// e1.printStackTrace();
		// }

		long time = System.currentTimeMillis() / 1000 % 86400;
		byte[] btime = new byte[] { (byte) (time & 0xff),
				(byte) (time >> 8 & 0xff) };
		send_data = arraycat(send_data, btime);

		// 00 /01
		send_data = arraycat(send_data, new byte[] { 0x00, 0x00, 0x00, 0x00 });

		DatagramPacket send_packet = new DatagramPacket(send_data,
				send_data.length, logif.ServerAddress, logif.port);

		ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE, "\r发送心跳包,time="
				+ time));
		try {
			socket.send(send_packet);
		} catch (IOException e) {
			e.printStackTrace();
			ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE, "发送心跳包失败\n"));
		}
		return true;
	}

	private boolean Send_Login_Auth(byte[] recv_data) {
		// ////////////////////////////////////////////////////////////////////////
		// 发送第二个包
		// ////////////////////////////////////////////////////////////////////////

		// 构造认证包
		byte[] data_head = new byte[4];
		data_head[0] = 0x03; // type
		data_head[1] = 0x01; // type
		data_head[2] = 0x00; // 结束标志
		data_head[3] = (byte) (logif.UserName.length() + 20); // 用户名长度+20
		// the first MD5 calculation
		byte[] md5_content = { 0x03, 0x01 };
		md5_content = arraycat(md5_content, service_identifier);
		md5_content = arraycat(md5_content, logif.PassWord.getBytes());

		login_a_md5 = md5_key(md5_content);

		byte[] username_zero = new byte[36 + 2];
		System.arraycopy(logif.UserName.getBytes(), 0, username_zero, 0,
				logif.UserName.length());
		// username_zero[36] = 0x09;
		username_zero[36] = 0x20; // 登陆类型内外网 40内网、20外网
		username_zero[37] = 0x01;

		int mac_length = logif.src_mac.length;
		byte[] mac_xor = new byte[mac_length];
		// MAC Address XOR calculation
		for (int i = 0; i < mac_length; i++)
			mac_xor[i] = (byte) (logif.src_mac[i] ^ login_a_md5[i]);

		// // the second MD5 calculation
		md5_content = new byte[] { 0x01 };
		md5_content = arraycat(md5_content, logif.PassWord.getBytes());
		md5_content = arraycat(md5_content, service_identifier);
		md5_content = arraycat(md5_content, new byte[4]);

		byte[] login_b_md5 = md5_key(md5_content);
		byte[] nic_ip_zero = new byte[12];
		byte[] num_nic = { 1 };

		// // the third MD5 calculation
		byte[] data_front = arraycat(data_head, login_a_md5);
		data_front = arraycat(data_front, username_zero);
		data_front = arraycat(data_front, mac_xor);
		data_front = arraycat(data_front, login_b_md5);
		data_front = arraycat(data_front, num_nic);
		data_front = arraycat(data_front,
				logif.nif.addresses[0].address.getAddress());
		data_front = arraycat(data_front, nic_ip_zero);

		md5_content = arraycat(data_front,
				new byte[] { 0x14, 0x00, 0x07, 0x0b }); // md5_tail
		byte[] login_c_md5 = new byte[8];

		byte[] c_md5 = md5_key(md5_content);
		System.arraycopy(c_md5, 0, login_c_md5, 0, 8);

		// // Add host DNS address
		byte[] host_name = new byte[32];

		String str_host_name = logif.nif.addresses[0].address.getHostName();
		System.arraycopy(str_host_name.getBytes(), 0, host_name, 0,
				str_host_name.getBytes().length);

		// // FIXME: not valid for "drcom v3.72 u31 2227 build"
		// dhcp='\x00'*4
		byte[] dhcp = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

		// // Add host system info
		byte[] host_unknown0 = { (byte) 0x94, 0x00, 0x00, 0x00 };
		byte[] os_major = { (byte) 0x06, 0x00, 0x00, 0x00 };
		byte[] os_minor = { (byte) 0x01, 0x00, 0x00, 0x00 };
		byte[] os_build = { (byte) 0xB0, 0x1D, 0x00, 0x00 };
		byte[] host_unknown1 = { (byte) 0x02, 0x00, 0x00, 0x00 };
		byte[] kernel_version = new byte[32];

		byte[] host_info = arraycat(host_name, logif.host_dnsp.getAddress());
		host_info = arraycat(host_info, dhcp);
		host_info = arraycat(host_info, logif.host_dnss.getAddress());
		host_info = arraycat(host_info, new byte[8]);
		host_info = arraycat(host_info, host_unknown0);
		host_info = arraycat(host_info, os_major);
		host_info = arraycat(host_info, os_minor);
		host_info = arraycat(host_info, os_build);
		host_info = arraycat(host_info, host_unknown1);
		host_info = arraycat(host_info, kernel_version);

		byte[] zero3 = new byte[96];

		// 第一个字节似乎是版本
		byte[] md5left = { 0x09, 0x00, 0x02, 0x0C,/* { */0x00, 0x00, 0x00,
				0x00/* } */, 0x00, 0x00 };

		System.arraycopy(c_md5, 10, md5left, 4, 4);

		// // FIXME: not valid for "drcom v3.72 u31 2227 build"
		// send_data=data_front+login_c_md5+chr(ip_dog)+'\x00'*4+host_info+zero3+\
		// unknown+'\x00'*6+chr(auto_logout)+chr(multicast_mode)+'\xf9\xf7'

		send_data = arraycat(data_front, login_c_md5);
		send_data = arraycat(send_data, new byte[] { 0x01, 0x00, 0x00, 0x00,
				0x00 }); // // AUTH bit chr(ip_dog)+'\x00'*4
		send_data = arraycat(send_data, host_info);
		send_data = arraycat(send_data, zero3);
		send_data = arraycat(send_data, md5left);
		send_data = arraycat(send_data, logif.src_mac);
		// auto_logout=0
		// multicast_mode=0
		send_data = arraycat(send_data, new byte[] { 0x00, 0x00 });
		send_data = arraycat(send_data, new byte[] { (byte) 0xf9, (byte) 0xf7 });
		DatagramPacket send_packet = new DatagramPacket(send_data,
				send_data.length, logif.ServerAddress, logif.port);

		ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE, "发送用户名、密码...\n"));
		try {
			socket.send(send_packet);
		} catch (IOException e) {
			e.printStackTrace();
			ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
					"发送 Login Auth失败！\n"));
			return false;
		}
		return true;
	}

	private boolean Send_Logout_Auth(byte[] recv_data) {
		// 构造认证包
		byte[] data_head = new byte[4];
		data_head[0] = 0x06; // type
		data_head[1] = 0x01; // type
		data_head[2] = 0x00; // 结束标志
		data_head[3] = (byte) (logif.UserName.length() + 20); // 用户名长度+20
		// // the first MD5 calculation
		byte[] md5_content = { 0x06, 0x01 };
		md5_content = arraycat(md5_content, service_identifier);
		md5_content = arraycat(md5_content, logif.PassWord.getBytes());

		login_a_md5 = md5_key(md5_content);

		// // MAC Address XOR calculation
		byte[] username_zero = new byte[36 + 2];
		System.arraycopy(logif.UserName.getBytes(), 0, username_zero, 0,
				logif.UserName.length());
		// username_zero[36] = 0x09;
		username_zero[36] = 0x20; // 0x89
		username_zero[37] = 0x01;

		// MAC Address XOR calculation
		int mac_length = logif.src_mac.length;
		byte[] mac_xor = new byte[mac_length];
		for (int i = 0; i < mac_length; i++)
			mac_xor[i] = (byte) (logif.src_mac[i] ^ login_a_md5[i]);

		send_data = arraycat(data_head, login_a_md5);
		send_data = arraycat(send_data, username_zero);
		send_data = arraycat(send_data, mac_xor);
		send_data = arraycat(send_data, auth_info);

		DatagramPacket send_packet = new DatagramPacket(send_data,
				send_data.length, logif.ServerAddress, logif.port);

		ml.ReciveMessage(new Message(Message.Msgtype.MESSAGE, "发送注销验证...\n"));
		try {
			socket.send(send_packet);
		} catch (IOException e) {
			e.printStackTrace();
			ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
					"发送 Logout Auth失败！\n"));
			return false;
		}
		return true;
	}

	private byte[] arraycat(byte[] buf1, byte[] buf2) {
		byte[] bufret = null;
		int len1 = 0;
		int len2 = 0;
		if (buf1 != null)
			len1 = buf1.length;
		if (buf2 != null)
			len2 = buf2.length;
		if (len1 + len2 > 0)
			bufret = new byte[len1 + len2];
		if (len1 > 0)
			System.arraycopy(buf1, 0, bufret, 0, len1);
		if (len2 > 0)
			System.arraycopy(buf2, 0, bufret, len1, len2);
		return bufret;
	}

	private byte[] md5_key(byte[] md5_content) {
		java.security.MessageDigest digest = null;
		try {
			digest = java.security.MessageDigest.getInstance("MD5");
			digest.update(md5_content);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return digest.digest();
	}

	@Override
	public void addMessageListener(MessageListener ml) {
		this.ml = ml;
	}

	private static final int byteArrayToInt(byte[] b, int pos) {
		return (b[pos + 3] << 24) + ((b[pos + 2] & 0xFF) << 16)
				+ ((b[pos + 1] & 0xFF) << 8) + (b[pos] & 0xFF);
	}

	@Override
	public void run() {
		// TODO Auto-generated method stub
		if (!Start() && state == State.LOGIN) {
			ml.ReciveMessage(new Message(Message.Msgtype.ERROR,
					"拨号失败，请输入q并回车以退出\n"));
		}
		alive.cancel();
	}
}
