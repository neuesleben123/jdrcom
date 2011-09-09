import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;

public class outerNetwork implements MessageAdapter {
	private static final int BEGIN_LOGIN_REQUEST_LEN = 20;

	String UserName;
	String PassWord;
	InetAddress ServerAddress;
	int port = 0xF000;

	MessageListener ml;

	public outerNetwork(String UserName, String PassWord,
			InetAddress ServerAddress, int port) {
		this.UserName = UserName;
		this.PassWord = PassWord;
		this.ServerAddress = ServerAddress;
		if (-1 != port)
			this.port = port;
	}

	public boolean login() {
		// 增加自动探测服务器地址 ...

		try {
			DatagramSocket socket = new DatagramSocket(port);// 16440
			byte buffer[] = new byte[256];

			while (true) {
				DatagramPacket packet = new DatagramPacket(buffer,
						buffer.length, ServerAddress, port);

				// ////////////////////////////////////////////////////////////////////////
				// 发送第一个包
				// ////////////////////////////////////////////////////////////////////////
				buffer[0] = 0x01; // type
				buffer[1] = 0x04; // 拨号次数（包括802.1X）
				// challenge ?
				buffer[2] = 0x00;
				buffer[3] = 0x00;

				buffer[4] = 0x09; // 固定 ，未知
				packet.setLength(BEGIN_LOGIN_REQUEST_LEN);

				socket.send(packet);

				// ////////////////////////////////////////////////////////////////////////
				// 接收第一个包
				// ////////////////////////////////////////////////////////////////////////
				socket.receive(packet);

				// 检查
				if (buffer[0] != 0x02) {
					ml.ReciveMessage(new Message(Message.ERROR,
							"登录失败。发出请求登录，服务器响应错误！"));
					return false;
				}

				byte[] challenge = new byte[4];
				System.arraycopy(challenge, 0, packet.getData(), 4, 4);

				// ////////////////////////////////////////////////////////////////////////
				// 发送第二个包
				// ////////////////////////////////////////////////////////////////////////
				buffer = new byte[330];
				packet = new DatagramPacket(buffer, buffer.length,
						ServerAddress, port);

				// 构造认证包
				buffer[0] = 0x03; // type
				buffer[1] = 0x01;

				buffer[2] = 0x00;
				buffer[3] = 0x1d; // 固定，未知

				java.security.MessageDigest digest;
				digest = java.security.MessageDigest.getInstance("MD5");
				digest.update(("\03\01" + new String(challenge) + PassWord)
						.getBytes());
				System.arraycopy(digest.digest(), 0, buffer, 4, 16); //MD5
				
				System.arraycopy(UserName.getBytes(), 0, buffer, 4 +16, UserName.length()); // 用户名
				
				buffer[4 +16 +36] = 0x20;
				buffer[4 +16 +36 +1] = 0x01;
				
				
				
				buffer[4 +16 +36 +1 +22] = 0x01;
				System.arraycopy(InetAddress.getLocalHost().getAddress(),0,buffer,4 +16 +36 +1 +22+1,4); //IP
				

				socket.send(packet);

				// ////////////////////////////////////////////////////////////////////////
				// 接收第二个包
				// ////////////////////////////////////////////////////////////////////////
				socket.receive(packet);

				byte[] recv_buf2 = packet.getData();

				// 检查登录是否成功
				if (recv_buf2[0] != 0x04) {
					// the other person have login in..
					if (recv_buf2[0] == 0x05 && recv_buf2[4] == 0x01) {
						// offset: 5: in use IP 4byte;
						// offset: 9: in use MAC 6 byte;
						String IP = String.format("IP:%d.%d.%d.%d ",
								recv_buf2[5], recv_buf2[6], recv_buf2[7],
								recv_buf2[8]);
						String MAC = String.format(
								"MAC:%02X-%02X-%02X-%02X-%02X-%02X ",
								recv_buf2[9], recv_buf2[10], recv_buf2[11],
								recv_buf2[12], recv_buf2[13], recv_buf2[14]);

						ml.ReciveMessage(new Message(Message.ERROR, "改账号已在"
								+ IP + MAC + "上登录！"));
						return false;
					}
					// Username or password error!
					else if (recv_buf2[0] == 0x05 && recv_buf2[4] == 0x03) {
						ml.ReciveMessage(new Message(Message.ERROR,
								"用户名或密码不对，请重新输入！"));
						return false;
					}
					// exceed the balance.....
					else if (recv_buf2[0] == 0x05 && recv_buf2[4] == 0x04) {
						ml.ReciveMessage(new Message(Message.ERROR,
								"费用超支，不能上网！"));
						return false;
					}
					// == 0x04 : success
					else {
						ml.ReciveMessage(new Message(Message.ERROR,
								"登录失败。发出登录认证包，可能服务器没有通过验证，请查看是否需要升级客户端程序!"));
						return false;
					}
				}
			}

		} catch (SocketException e) {
			e.printStackTrace();
			ml.ReciveMessage(new Message(Message.MESSAGE,
					"端口绑定失败，请检查是否有其他客户端在运行！"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return true;
	}

	public boolean logoff() {

		return false;
	}

	@Override
	public void addMessageListener(MessageListener ml) {
		// TODO Auto-generated method stub
		this.ml = ml;
	}

}
