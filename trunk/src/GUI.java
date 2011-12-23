import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Choice;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Label;
import java.awt.Panel;
import java.awt.TextArea;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.IOException;
import java.util.Properties;
import java.awt.*;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class GUI implements ActionListener, WindowListener, ItemListener,
		MessageListener {
	LoginInfo logif = new LoginInfo();

	public static String Itemtemp;
	TextArea area_feedback;
	TextField textFieldusername;
	TextField textFieldpwd;
	Choice choice_netcard;
	Frame f1 = new Frame("校园网登陆");

	public void paint() {
		f1.addWindowListener(this); // 关闭窗口
		f1.setSize(200, 200);
		f1.setSize(100, 200);
		f1.setLayout(new GridBagLayout());

		int fill[] = { GridBagConstraints.BOTH, // 上下左右填满
				GridBagConstraints.VERTICAL, // 上下填满
				GridBagConstraints.HORIZONTAL, // 左右填满
				GridBagConstraints.NONE }; // 保持原来大小

		int anchor[] = {
				GridBagConstraints.CENTER, // 方位
				GridBagConstraints.EAST, GridBagConstraints.SOUTH,
				GridBagConstraints.SOUTHEAST, GridBagConstraints.SOUTHWEST,
				GridBagConstraints.WEST, GridBagConstraints.NORTH,
				GridBagConstraints.NORTHEAST, GridBagConstraints.NORTHWEST };

		int att[][] = {
		// 起始列 ，起始行，宽 ,高 ,格宽,格高，填充， 填充方位， 间距top left bottom right ,最佳间距

				{ 2, 0, 2, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // chioce_netcard
				{ 0, 1, 2, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // label_username
				{ 0, 2, 2, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // label_pwd
				{ 2, 1, 2, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // textFieldusername
				{ 2, 2, 2, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // textFieldpwd
				{ 0, 3, 1, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // btn_inter_login
				{ 1, 3, 1, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // btn_internet_login
				{ 2, 3, 1, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // btn_inter_logout
				{ 3, 3, 1, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // btn_internet_logout
				{ 0, 5, 4, 2, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // area_feedback
				{ 0, 0, 2, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // label_netcardname
				{ 0, 4, 2, 1, 1, 1, fill[0], anchor[0], 1, 1, 1, 1, 5, 5 }, // lable_logfeedback

		};

		f1.setBackground(Color.green);

		Button btn_inter_login = new Button("内网登录");
		Button btn_internet_login = new Button("外网登录");
		Button btn_inter_logout = new Button("内网下线");
		Button btn_internet_logout = new Button("外网下线");

		btn_inter_login.addActionListener(this);
		btn_inter_login.setActionCommand("btn_inter_log");

		btn_internet_login.addActionListener(this);
		btn_internet_login.setActionCommand("btn_internet_login");

		btn_inter_logout.addActionListener(this);
		btn_inter_logout.setActionCommand("btn_inter_logout");

		btn_internet_logout.addActionListener(this);
		btn_internet_logout.setActionCommand("btn_internet_logout");

		Label label_username = new Label("用户名：");
		Label label_pwd = new Label("密    码：");

		textFieldusername = new TextField(15);
		textFieldpwd = new TextField(15);

		textFieldpwd.setEchoChar('*');

		area_feedback = new TextArea(6, 25);
		area_feedback.setBackground(Color.white);
		area_feedback.setForeground(Color.white);
		
		area_feedback.setEnabled(false);
		
		
		choice_netcard = new Choice();
		choice_netcard.addItemListener(new GUI());

		for (NetworkInterface n : JpcapCaptor.getDeviceList()) {
			// System.out.printf("网卡名称:%s\n描述:%s\n\n", n.name,n.description);
			choice_netcard.add(n.description);
		}

		Label labelnetcardname = new Label("请选择网卡:");
		add(f1, labelnetcardname, att[10]);
		add(f1, choice_netcard, att[0]);

		add(f1, label_username, att[1]);
		add(f1, label_pwd, att[2]);

		add(f1, textFieldusername, att[3]);
		add(f1, textFieldpwd, att[4]);

		add(f1, btn_inter_login, att[5]);
		add(f1, btn_internet_login, att[6]);
		add(f1, btn_inter_logout, att[7]);
		add(f1, btn_internet_logout, att[8]);

		Label lable_logfeedback = new Label("登录情况反馈:");
		add(f1, lable_logfeedback, att[11]);
		add(f1, area_feedback, att[9]);

		f1.pack();
		f1.setVisible(true);
	}

	// GridBagLayout 属性
	private static void add(Container con, Component com, int att[]) {
		GridBagConstraints cons = new GridBagConstraints();
		cons.gridx = att[0];
		cons.gridy = att[1];
		cons.gridwidth = att[2];
		cons.gridheight = att[3];
		cons.weightx = att[4];
		cons.weighty = att[5];
		cons.fill = att[6];
		cons.anchor = att[7];
		cons.insets = new Insets(att[8], att[9], att[10], att[11]);// top left
		// bottom
		// right
		cons.ipadx = att[12];
		cons.ipady = att[13];

		con.add(com, cons);
	}

	// closing
	public void windowClosing(WindowEvent e) {
		System.exit(0);
	}

	public void windowDeactivated(WindowEvent e) {
	}

	public void windowActivated(WindowEvent e) {
	}

	public void windowOpened(WindowEvent e) {
	}

	public void windowIconified(WindowEvent e) {
	}

	public void windowClosed(WindowEvent e) {
	}

	public void windowDeiconified(WindowEvent e) {
	}

	// combox
	public void itemStateChanged(ItemEvent e) {
		if (e.getStateChange() == e.SELECTED) { // 这里控制为只处理一次
			// System.out.println( "选中了 ");
			Choice c = (Choice) e.getSource();
			Itemtemp = c.getSelectedItem();
		}

		// System.out.println("selected item index: " + c.getSelectedIndex());
		// System.out.println("selected item : " + c.getSelectedItem());

	}

	// @Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub

		String getuser1, getpwd2;
		String cmd = e.getActionCommand();
		getuser1 = textFieldusername.getText();
		getpwd2 = textFieldpwd.getText();
		logif.UserName = getuser1;
		logif.PassWord = getpwd2;

		for (NetworkInterface n : JpcapCaptor.getDeviceList())
			if (n.description.equals(Itemtemp))
				logif.nif = n;

		logif.src_mac = logif.nif.mac_address;
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
		System.out.print(logif);

		if (cmd.equals("btn_inter_log")) {

			IntranetNetwork in = new IntranetNetwork(logif);
			in.addMessageListener(this);
			System.out.println("正在执行one");
			in.Start();
			// System.out.print(getuser1);
		} else {
			if (cmd.equals("btn_inter_logout")) {
				IntranetNetwork in = new IntranetNetwork(logif);
				in.addMessageListener(this);
				in.logoff();
			} else {
				if (cmd.equals("btn_internet_login")) {
					InternetNetwork out = null;
					try {
						out = new InternetNetwork(logif);
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						System.out.println("端口绑定失败，请检查是否有其他客户端在运行！");
						// return 0;
					}
					out.addMessageListener(this);
					Thread thd = new Thread(out);

					thd.start();

					while (thd.isAlive()) {
						// System.out.print("\n等待命令:");

						out.Send_Alive();
						out.Output_Infomation();
					}// ONLINE
					out.state = InternetNetwork.State.STOP;

					/*
					 * catch (IOException ex) { // TODO Auto-generated catch
					 * block ex.printStackTrace(); }
					 */

				} else if (cmd.equals("btn_internet_logout")) {

					InternetNetwork out = null;

					// out = new InternetNetwork(logif);

					try{
					out.addMessageListener(this);}
					catch(Exception e3)
					{}
					Thread thd = new Thread(out);
					thd.start();
					while (out.state != InternetNetwork.State.ONLINE);

					out.state = InternetNetwork.State.STOP;

				}
			}
		}
	}

	@Override
	public void ReciveMessage(Message msg) {
		// TODO Auto-generated method stub
		area_feedback.append(msg.msg);
		switch (msg.type) {
		case INNERSUCCESS:
			area_feedback.append("获取IP地址...(" + logif.dhcpScript + ")" + "\n");
			try {
				Runtime.getRuntime().exec(logif.dhcpScript);
			} catch (IllegalArgumentException e) {
				// TODO: handle exception
				area_feedback.append("DHCP脚本运行错误！请手动设置获取IP" + "\n");
				return;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return;
			}
			area_feedback.append("如不能上网请检查网卡是否设置为自动获取IP，DNS是否正确" + "\n");
			break;
		case OUTTERSUCCESS:
			area_feedback.append("注销请按q+回车，查询实时信息请按i+回车！");
			break;
		}
	}

}