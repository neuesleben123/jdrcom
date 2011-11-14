import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;

/*## basic network parameters
 self.BUFFER = 1024
 self.server_brand = 'Drco'
 self.ifname = self.get_ifname()
 self.md5_tail = '\x14\x00\x07\x0b'
 self.host_ip = self.get_ip_addr()
 self.host_ip_dec = socket.inet_ntoa(self.host_ip)
 self.mac_addr = self.get_mac_addr()

 ## Packet ID
 self.host_packet_id = {
 '_login_request_'   :'\x01\x10',
 '_login_auth_'      :'\x03\x01',
 '_logout_request_'  :'\x01\x0e',
 '_logout_auth_'     :'\x06\x01',
 '_passwd_request_'  :'\x01\x0d',
 '_new_passwd_'      :'\x09\x01',
 '_alive_40_client_' :'\x07',
 '_alive_38_client_' :'\xff',
 '_alive_4_client_'  :'\xfe',
 }
 self.server_packet_id = {
 '\x02\x10'    :'_login_response_',
 '\x02\x0e'    :'_logout_response_',
 '\x02\x0d'    :'_passwd_response_',
 '\x04\x00'    :'_success_',
 '\x05\x00'    :'_failure_',
 '\x07'        :'_alive_40_server_',
 '\x07\x01\x10':'_alive_38_server_',
 '\x4d\x26'    :'_alive_4_server_',
 '\x4d\x38'    :'_Serv_Info_',
 '\x4d\x3a'    :'_Notice_',
 }

 ## parameters used in keep_alive
 self.alive_account0 = 0x1a
 self.alive_account1 = 0x2e
 self.server_ack_40 = '\x12\x56\xd3\x03'

 ## local address array
 self.local_addr = []
 self.local_mask = []

 self.timer_38 = 200
 self.timer_40 = 160
 self.module_auth = 'non-AUTH'

 */

public class outerNetwork implements MessageAdapter {
	private static final int BEGIN_LOGIN_REQUEST_LEN = 20;

	LoginInfo logif;

	int port = 0xF000; // 默认端口

	MessageListener ml;

	public outerNetwork(LoginInfo logif, int port) {
		this.logif = logif;
		if (-1 != port)
			this.port = port;
	}

	byte[] arraycat(byte[] buf1, byte[] buf2) {
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

	byte[] md5_key(byte[] md5_content) {
		java.security.MessageDigest digest = null;
		try {
			digest = java.security.MessageDigest.getInstance("MD5");
			digest.update(md5_content);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return digest.digest();
	}

	public boolean login() {
		// 增加自动探测服务器地址

		try {
			DatagramSocket socket = new DatagramSocket(port);// 16440
			byte recv_data[] = new byte[256];
			byte send_data[] = new byte[20];

			while (true) {
				DatagramPacket recv_packet = new DatagramPacket(recv_data,
						recv_data.length);

				// ////////////////////////////////////////////////////////////////////////
				// 发送第一个包
				// ////////////////////////////////////////////////////////////////////////
				send_data[0] = 0x01; // type
				send_data[1] = 0x00; // 拨号次数（包括802.1X）
				// challenge ?
				send_data[2] = 0x00;
				send_data[3] = 0x00;

				send_data[4] = 0x09; // 固定 ，版本？

				DatagramPacket send_packet = new DatagramPacket(send_data,
						send_data.length, logif.ServerAddress, port);

				send_packet.setLength(BEGIN_LOGIN_REQUEST_LEN);

				socket.send(send_packet);

				// ////////////////////////////////////////////////////////////////////////
				// 接收第一个包
				// ////////////////////////////////////////////////////////////////////////
				socket.receive(recv_packet);

				// 检查
				if (recv_data[0] != 0x02) {
					ml.ReciveMessage(new Message(Message.ERROR,
							"登录失败。发出请求登录，服务器响应错误！"));
					return false;
				}

				byte[] service_identifier = new byte[] { (byte) 0xdb, 0x5b,
						0x01, 0x00 };

				/*System.arraycopy(recv_packet.getData(), 4, service_identifier,
						0, 4);
*/
				// ////////////////////////////////////////////////////////////////////////
				// 发送第二个包
				// ////////////////////////////////////////////////////////////////////////

				// 构造认证包
				byte[] data_head = new byte[4];
				data_head[0] = 0x03; // type
				data_head[1] = 0x01; // type
				data_head[2] = 0x00; // 结束标志
				data_head[3] = (byte) (logif.UserName.length() + 20); // 用户名长度+20
				// // the first MD5 calculation
				byte[] md5_content = { 0x03, 0x01 };
				md5_content = arraycat(md5_content, service_identifier);
				md5_content = arraycat(md5_content, logif.PassWord.getBytes());

				byte[] login_a_md5 = md5_key(md5_content);

				// // MAC Address XOR calculation
				byte[] username_zero = new byte[36 + 2];
				System.arraycopy(logif.UserName.getBytes(), 0, username_zero,
						0, logif.UserName.length());
				//username_zero[36] = 0x09;
				username_zero[36] = 0x20;
				username_zero[37] = 0x01;

				int mac_length = logif.src_mac.length;
				byte[] mac_xor = new byte[mac_length];

				for (int i = 0; i < mac_length; i++)
					mac_xor[i] = (byte) (logif.src_mac[i] ^ login_a_md5[i]);

				// // the second MD5 calculation
				md5_content = new byte[] { 0x01 };
				md5_content=arraycat(md5_content, logif.PassWord.getBytes());
				md5_content=arraycat(md5_content, service_identifier);
				md5_content=arraycat(md5_content, new byte[4]);

				byte[] login_b_md5 = md5_key(md5_content);
				byte[] nic_ip_zero = new byte[12];
				byte[] num_nic = { 1 };

				// // the third MD5 calculation
				byte[] data_front = arraycat(data_head, login_a_md5);
				data_front = arraycat(data_front, username_zero);
				data_front = arraycat(data_front, mac_xor);
				data_front = arraycat(data_front, login_b_md5);
				data_front = arraycat(data_front, num_nic);
				data_front = arraycat(data_front, InetAddress.getLocalHost()
						.getAddress());
				data_front = arraycat(data_front, nic_ip_zero);

				md5_content = arraycat(data_front, new byte[] { 0x14, 0x00,
						0x07, 0x0b }); // md5_tail
				byte[] login_c_md5 = new byte[8];
				System.arraycopy(md5_key(md5_content), 0, login_c_md5, 0, 8);

				// // Add host DNS address
				byte[] host_name = new byte[32];

				String str_host_name = InetAddress.getLocalHost().getHostName();
				System.arraycopy(str_host_name.getBytes(), 0, host_name, 0,
						str_host_name.getBytes().length);

				// // FIXME: not valid for "drcom v3.72 u31 2227 build"
				// dhcp='\x00'*4
				byte[] dhcp = { (byte) 0xff, (byte) 0xff, (byte) 0xff,
						(byte) 0xff };

				// // Add host system info
				byte[] host_unknown0 = { (byte) 0x94, 0x00, 0x00, 0x00 };
				byte[] os_major = { (byte) 0x06, 0x00, 0x00, 0x00 };
				byte[] os_minor = { (byte) 0x01, 0x00, 0x00, 0x00 };
				byte[] os_build = { (byte) 0xB0, 0x1D, 0x00, 0x00 };
				byte[] host_unknown1 = { (byte) 0x02, 0x00, 0x00, 0x00 };
				byte[] kernel_version = new byte[32];

				byte[] host_info = arraycat(host_name,
						logif.host_dnsp.getAddress());
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

				// // FIXME: not valid for "drcom v3.72 u31 2227 build"
				// unknown='\x03\x00\x02\x0C'+'\x20\x02\x60\x1a\x00\x00'
				// byte[] unknown = { 0x03, 0x00, 0x02, 0x0C, 0x00, (byte) 0xF3,
				// 0x31,(byte) 0x9F, 0x01, 0x00 };
				// 第一个字节似乎是版本
				byte[] unknown = { 0x09, 0x00, 0x02, 0x0C, 0x00, (byte) 0xF1,
						0x76, (byte) 0x24, 0x00, 0x00 };

				// // FIXME: not valid for "drcom v3.72 u31 2227 build"
				// send_data=data_front+login_c_md5+chr(ip_dog)+'\x00'*4+host_info+zero3+\
				// unknown+'\x00'*6+chr(auto_logout)+chr(multicast_mode)+'\xf9\xf7'

				send_data = arraycat(data_front, login_c_md5);
				send_data = arraycat(send_data, new byte[] { 0x01, 0x00, 0x00,
						0x00, 0x00 }); // // AUTH bit chr(ip_dog)+'\x00'*4
				send_data = arraycat(send_data, host_info);
				send_data = arraycat(send_data, zero3);
				send_data = arraycat(send_data, unknown);
				send_data = arraycat(send_data, logif.src_mac);
				send_data = arraycat(send_data, new byte[] { 0x00, 0x00 }); // auto_logout=0;	// multicast_mode=0
				send_data = arraycat(send_data, new byte[] { (byte) 0xf9, (byte) 0xf7 });
				send_packet = new DatagramPacket(send_data, send_data.length,
						logif.ServerAddress, port);
				socket.send(send_packet);

				// ////////////////////////////////////////////////////////////////////////
				// 接收第二个包
				// ////////////////////////////////////////////////////////////////////////
				socket.receive(recv_packet);

				byte[] recv_buf2 = recv_packet.getData();

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
