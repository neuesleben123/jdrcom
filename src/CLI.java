import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
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

	NetworkInterface nif;
	byte[] src_mac;
	byte[] dst_mac;
	String UserName;
	String PassWord;
	char type = 'i';
	Options options = new Options();

	public CLI() {

	}

	private void printHelp(Options options) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp("drcom", options);
	}

	private Options createOptions() {
		// create the Options

		options.addOption(OptionBuilder.withLongOpt("conf")
				.withArgName("filename").hasArg().withDescription("使用配置文件的参数")
				.create("c"));
		// 读取配置文件
		options.addOption("i", "intetface", true, "网卡");
		options.addOption("l", "list", false, "输出网卡列表");
		options.addOption("t", "type", true,
				"登陆类型 内网：i(inner) 外网：o(outter) 默认为i");
		options.addOption("u", "username", true, "用户名");
		options.addOption("p", "password", true, "密码,默认123456");
		options.addOption("svr", "serverip", true, "外网登陆服务器ip 默认自动搜索");// 为10.5.2.3
		options.addOption("ds", "dhcpscript", true,
				"内网拨号成功后自定义的自动获取IP脚本命令,Windows下默认为\"ipconfig /renew *\",Linux默认为\"dhcpc *\" ");
		options.addOption("s", "srcmac", true, "指定源MAC地址，比如你用别人的账号上网");
		options.addOption("d", "dstmac", true,
				"指定目的MAC地址，默认为01-80-C2-00-00-03，一般不用指定");
		options.addOption("h", "help", false, "显示此帮助");
		// String[] args = new String[]{ "--block-size=10" };

		return options;
	}

	public boolean run(String[] args) {

		// create the command line parser
		CommandLineParser parser = new PosixParser();

		createOptions();
		try {
			// parse the command line arguments
			CommandLine line = parser.parse(options, args);

			if (line.hasOption('h') || line.getOptions().length < 1) {
				printHelp(options);
				return true;
			}

			if (line.hasOption('l')) {
				if (JpcapCaptor.getDeviceList().length == 0)
					System.out.printf("没有找到网卡！" + "请检查是否以管理员权限运行本程序、或网卡是否已启用!");
				for (NetworkInterface n : JpcapCaptor.getDeviceList()) {
					System.out.printf("网卡名称:%s\n描述:%s\n\n", n.name,
							n.description);
				}
				return true;
			}

			if (line.hasOption('i')) {
				for (NetworkInterface n : JpcapCaptor.getDeviceList())
					if (n.name.equals(line.getOptionValue('i')))
						nif = n;
				if (nif == null) {
					System.out.println("网卡不存在!请使用-l显示网卡列表");
					return false;
				}
			} else {
				System.out.println("必须指定拨号所用网卡");
				return false;
			}

			if (line.hasOption('t')) {
				if (line.getOptionValue('t').matches("^o$|^outer$|^i$|^inner$")) {
					type = line.getOptionValue('t').charAt(0);
				}
			}

			if (line.hasOption('s')) {
				String strmac = line.getOptionValue('s').replaceAll(
						"[^A-Za-z0-9]", "");
				if (strmac.length() != 12) {
					System.out.println("不合法的源MAC地址！");
					return false;
				}
				src_mac = new BigInteger(strmac, 16).toByteArray();
				src_mac = Arrays.copyOfRange(src_mac, src_mac.length - 6,
						src_mac.length);
			} else {
				src_mac = nif.mac_address;
			}

			if (line.hasOption('d')) {
				String dstmac = line.getOptionValue('d').replaceAll(
						"[^A-Za-z0-9]", "");
				if (dstmac.length() != 12) {
					System.out.println("不合法的目的MAC地址！");
					return false;
				}
				dst_mac = new BigInteger(dstmac, 16).toByteArray();
			} else {
				dst_mac = nif.mac_address;
			}

			if (line.hasOption('u'))
				UserName = line.getOptionValue('u');
			else {
				System.out.println("必须指定用户名");
				return false;
			}

			PassWord = line.getOptionValue('p', "123456");

		} catch (ParseException exp) {
			System.out.println("错误:" + exp.getMessage());
			return false;
		}

		// if (args[1].equals("802on")) {;

		switch (type) {
		case 'i':
			innerNetwork in = new innerNetwork(nif, src_mac, dst_mac, UserName,
					PassWord);
			in.addMessageListener(this);
			in.login();
			break;
		case 'o':
			InetAddress address;
			try {
				address = InetAddress.getByAddress(new byte[] { 10, 5, 2, 3 });
				outerNetwork out = new outerNetwork(UserName, PassWord,
						address, -1);
				out.addMessageListener(this);
				out.login();
			} catch (UnknownHostException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			break;
		default:
			break;
		}

		return true;
	}

	@Override
	public void ReciveMessage(Message msg) {
		// TODO Auto-generated method stub
		System.out.println(msg.msg);

		if (msg.type == Message.SUCCESS)
			try {
				Properties props = System.getProperties();
				if (props.getProperty("os.name").contains("indows")) {
					System.out.println("获取IP地址...");
					Runtime.getRuntime().exec("ipconfig /renew *");
					System.out.println("如不能上网请检查网卡是否设置为自动获取IP，DNS是否正确");
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	}
}
