import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

class CLI implements MessageListener {

	LoginInfo logif = new LoginInfo();

	enum Type {
		INTRANET, INTERNET
	};

	Type type = Type.INTRANET;

	enum Action {
		LOGIN, LOGOUT
	};

	Action action = Action.LOGIN;

	Options options = new Options();
	String cmdLineSyntax = "java -jar jdrcom.jar [-OPTIONS]"
			+ "\njava版的dr.com的开源拨号客户端\n";

	public boolean run(String[] args) {

		if (!args_Handler(args))
			return false;

		switch (type) {
		case INTRANET:
			IntranetNetwork in = new IntranetNetwork(logif);
			in.addMessageListener(this);
			switch (action) {
			case LOGIN:
				in.run();
				break;
			case LOGOUT:
				in.logoff();
				break;
			}
			break;
		case INTERNET:
			InternetNetwork out = null;
			try {
				out = new InternetNetwork(logif);
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				System.out.println("端口绑定失败，请检查是否有其他客户端在运行！");
				break;
			}
			out.addMessageListener(this);
			Thread thd = new Thread(out);
			switch (action) {
			case LOGIN:
				thd.start();
				try {
					labrun: while (thd.isAlive()) {
						// System.out.print("\n等待命令:");
						switch (System.in.read()) {
						case 'i':
						case 'I':
							out.Send_Alive();
							out.Output_Infomation();
							break;
						case 'q':
						case 'Q':
							System.out.println("开始注销...");
							break labrun;
						}
					}// ONLINE
					out.state = InternetNetwork.State.STOP;
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				break;
			case LOGOUT:
				thd.start();
				while (out.state != InternetNetwork.State.ONLINE)
					;
				out.state = InternetNetwork.State.STOP;
				break;
			}
			break;
		}
		return true;
	}

	private void printHelp(Options options) {
		System.out
				.println("\n因学校无IPV6环境，无法测试，本软件暂不支持IPV6！如果你想帮助作者完善请访问 https://code.google.com/p/jdrcom/\n");
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp(cmdLineSyntax, options);
	}

	@SuppressWarnings("static-access")
	private Options createOptions() {
		// create the Options

		options.addOption(OptionBuilder.withLongOpt("conf")
				.withArgName("filename").hasArg().withDescription("使用配置文件的参数")
				.create("c"));
		// 读取配置文件
		options.addOption("i", "intetface", true, "指定拨号网卡名");
		options.addOption("l", "list", false, "列出本机所有网卡名");
		options.addOption("t", "type", true,
				"登录类型 内网：i(INTRANET) 外网：o(outter) 默认为内网");
		options.addOption("a", "action", true,
				"登录还是注销 登录：i(login) 注销：o(logout) 默认为登录");
		options.addOption("u", "username", true, "指定用户名");
		options.addOption("p", "password", true, "指定密码,如不指定则默认123456");
		options.addOption("svr", "serverip", true, "外网登录服务器ip 默认自动搜索");// 为10.5.2.3
		options.addOption("ds", "dhcpscript", true,
				"内网拨号成功后自定义的自动获取IP脚本命令\nWindows下默认为\"ipconfig /renew *\"\n其他系统无默认值，请自行配置！");
		options.addOption("s", "srcmac", true, "指定源MAC地址，当你用别人的账号上网时需要指定");
		options.addOption("d", "dstmac", true,
				"指定目的MAC地址,默认为01-80-C2-00-00-03,一般不用指定");
		options.addOption("h", "help", false, "显示此帮助");

		return options;
	}

	private boolean args_Handler(String[] args) {
		// TODO Auto-generated method stub

		// create the command line parser
		CommandLineParser parser = new PosixParser();

		createOptions();
		try {
			// parse the command line arguments
			CommandLine line = parser.parse(options, args);

			if (line.hasOption('h') || line.getOptions().length < 1) {
				printHelp(options);
				return false;
			}

			if (line.hasOption('l')) {
				System.out
						.println("如提示“无法打开共享对象文件: 没有那个文件或目录”等错误，请检查是否以管理员权限运行本程序、或网卡是否已启用!\n");
				if (JpcapCaptor.getDeviceList().length == 0)
					System.out
							.println("没有找到网卡！" + "请检查是否以管理员权限运行本程序、或网卡是否已启用!");
				for (NetworkInterface n : JpcapCaptor.getDeviceList()) {
					System.out.printf("网卡名称:%s\n描述:%s\n\n", n.name,
							n.description);
				}
				return false;
			}

			if (line.hasOption('i')) {
				for (NetworkInterface n : JpcapCaptor.getDeviceList())
					if (n.name.equals(line.getOptionValue('i')))
						logif.nif = n;
				if (logif.nif == null) {
					System.out.println("网卡不存在!请使用-l显示网卡列表");
					return false;
				}
			} else {
				System.out.println("必须指定拨号所用网卡");
				return false;
			}

			if (line.hasOption('t')) {
				if (line.getOptionValue('t').matches("^i$|^INTRANET$")) {
					type = Type.INTRANET;
				} else if (line.getOptionValue('t').matches("^o$|^INTERNET$")) {
					type = Type.INTERNET;
				} else {
					System.out.println("未知登录类型！");
					return false;
				}
			}
			if (line.hasOption('a')) {
				if (line.getOptionValue('a').matches("^i$|^login$")) {
					action = Action.LOGIN;
				} else if (line.getOptionValue('a').matches("^o$|^logout$")) {
					action = Action.LOGOUT;
				} else {
					System.out.println("未知Action！");
					return false;
				}
			}

			if (line.hasOption("svr")) {
				try {
					logif.ServerAddress = InetAddress.getByName(line
							.getOptionValue("svr"));
				} catch (UnknownHostException e) {
					// TODO Auto-generated catch block
					System.out.println("服务器ip格式错误！");
					return false;
					// e.printStackTrace();
				}
			}

			if (line.hasOption('s')) {
				String strmac = line.getOptionValue('s').replaceAll(
						"[^A-Za-z0-9]", "");
				if (strmac.length() != 12) {
					System.out.println("不合法的源MAC地址！");
					return false;
				}
				logif.src_mac = new byte[6];

				long mac = Long.parseLong(strmac, 16);
				logif.src_mac[5] = (byte) (mac & 0xff);
				logif.src_mac[4] = (byte) (mac >> 8 & 0xff);
				logif.src_mac[3] = (byte) (mac >> 16 & 0xff);
				logif.src_mac[2] = (byte) (mac >> 24 & 0xff);
				logif.src_mac[1] = (byte) (mac >> 32 & 0xff);
				logif.src_mac[0] = (byte) (mac >> 40 & 0xff);

			} else {
				logif.src_mac = logif.nif.mac_address;
			}

			if (line.hasOption('d')) {
				String dstmac = line.getOptionValue('d').replaceAll(
						"[^A-Za-z0-9]", "");
				if (dstmac.length() != 12) {
					System.out.println("不合法的目的MAC地址！");
					return false;
				}
				logif.dst_mac = new BigInteger(dstmac, 16).toByteArray();
			} else {
				logif.dst_mac = logif.nif.mac_address;
			}

			if (line.hasOption('u'))
				logif.UserName = line.getOptionValue('u');
			else {
				System.out.println("必须指定用户名");
				return false;
			}

			logif.PassWord = line.getOptionValue('p', "123456");

			Properties props = System.getProperties();
			if (props.getProperty("os.name").contains("indows")) {
				logif.os = OS.Windows;
				logif.dhcpScript = "ipconfig /renew *";
			} else if (props.getProperty("os.name").contains("Linux")) {
				logif.os = OS.Linux;
				logif.dhcpScript = "";
			} else {
				logif.os = OS.Others;
				logif.dhcpScript = "";
			}

			if (line.hasOption("ds")) {
				logif.dhcpScript = line.getOptionValue("ds");
			}

		} catch (ParseException exp) {
			System.out.println("错误:" + exp.getMessage());
			return false;
		}

		return true;
	}

	@Override
	public void ReciveMessage(Message msg) {
		// TODO Auto-generated method stub
		System.out.print(msg.msg);
		switch (msg.type) {
		case INNERSUCCESS:
			System.out.println("获取IP地址...(" + logif.dhcpScript + ")");
			try {
				Runtime.getRuntime().exec(logif.dhcpScript);
			} catch (IllegalArgumentException e) {
				// TODO: handle exception
				System.out.println("DHCP脚本运行错误！请手动设置获取IP");
				return;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return;
			}
			System.out.println("如不能上网请检查网卡是否设置为自动获取IP，DNS是否正确");
			break;
		case OUTTERSUCCESS:
			System.out.println("注销请按q+回车，查询实时信息请按i+回车！");
			break;
		}
	}
}
