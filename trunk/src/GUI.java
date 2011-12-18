import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Choice;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.Label;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.IOException;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class GUI implements ActionListener, WindowListener, ItemListener,
		MessageListener {
	LoginInfo logif = new LoginInfo();
	TextField textFieldusername;
	TextField textFieldpwd;
	Choice ch;
	Frame f1 = new Frame();

	public void paint() {
		f1.addWindowListener(this); // 关闭窗口
		// Frame f2 =new Frame("lixiang");

		f1.setSize(100, 200);
		// f1.setSize(100,200);
		// f1.setLayout(new GridLayout(5,5));

		f1.setBackground(Color.YELLOW);
		Button b1 = new Button("one");
		Button b2 = new Button("two");
		Button b3 = new Button("intramural logout");
		Button b4 = new Button("internet logout");
		Button b5 = new Button("five");

		BorderLayout e = new BorderLayout(0, 0);

		e.setHgap(5);
		e.setVgap(5);

		f1.setLayout(e);
		f1.setLayout(new FlowLayout());

		// FlowLayout f=new FlowLayout(FlowLayout.RIGHT,10,20);

		// f.setAlignment(FlowLayout.LEFT);

		f1.add(b1, BorderLayout.EAST);
		f1.add(b2, BorderLayout.NORTH);
		f1.add(b3, BorderLayout.SOUTH);
		f1.add(b4, BorderLayout.WEST);
		f1.add(b5, BorderLayout.CENTER);

		// CardLayout card;

		b1.addActionListener(this);
		b1.setActionCommand("one");

		b2.addActionListener(this);
		b2.setActionCommand("two");

		// b3.addActionListener(this);

		Label labelusername = new Label("username", Label.LEFT);
		f1.add(labelusername);
		Label labelpwd = new Label("password", Label.LEFT);

		f1.add(labelusername);
		f1.add(labelpwd);
		textFieldusername = new TextField(15);
		textFieldpwd = new TextField(15);

		textFieldpwd.setEchoChar('*');
		// int a[][]={{0,0,1,1}};
		f1.add(textFieldusername);
		f1.add(textFieldpwd);

		ch = new Choice();
		ch.addItemListener(new GUI());

		for (NetworkInterface n : JpcapCaptor.getDeviceList()) {
			// System.out.printf("网卡名称:%s\n描述:%s\n\n", n.name,n.description);
			ch.add(n.description);
		}
		f1.add(ch);
		// ChoiceExample(n.name) ;
		// showStatus(getuser);
		// f1.add(textFieldpwd);
		f1.pack();
		f1.setVisible(true);
		// f2.setVisible(true);
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
		Choice c = (Choice) e.getSource();
		System.out.println("selected item index: " + c.getSelectedIndex());
		System.out.println("selected item : " + c.getSelectedItem());

		for (NetworkInterface n : JpcapCaptor.getDeviceList())
			if (n.description.equals(c.getSelectedItem())) {
				logif.nif = n;
				break;
			}
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub

		String getuser1, getpwd2;
		String cmd = e.getActionCommand();
		getuser1 = textFieldusername.getText();
		getpwd2 = textFieldpwd.getText();
		logif.UserName = getuser1;
		logif.PassWord = getpwd2;

		// System.out.print(logif);
		if (cmd.equals("one")) {

			IntranetNetwork in = new IntranetNetwork(logif);
			in.addMessageListener(this);
			System.out.println("正在执行one");
			in.Start();
			System.out.print(getuser1);
		}

		else {
			if (cmd.equals("two")) {
				System.out.print(getpwd2);
			}
			// in.logoff();
		}
		/*
		 * else { if(cmd.equals("intramural logout")) { // in.logoff(); } else
		 * if(cmd.equals("logon internet")) { InternetNetwork out = null; try {
		 * out = new InternetNetwork(logif); } catch (Exception e1) { // TODO
		 * Auto-generated catch block
		 * System.out.println("端口绑定失败，请检查是否有其他客户端在运行！"); //break;
		 * out.addMessageListener(this); Thread thd = new Thread(out);
		 * 
		 * 
		 * 
		 * thd.start(); try { labrun: while (thd.isAlive()) { //
		 * System.out.print("\n等待命令:"); switch (System.in.read()) { case 'i':
		 * case 'I': out.Send_Alive(); out.Output_Infomation(); break; case 'q':
		 * case 'Q': System.out.println("开始注销..."); break labrun; } }// ONLINE
		 * out.state = InternetNetwork.State.STOP; } catch (IOException ex) { //
		 * TODO Auto-generated catch block ex.printStackTrace(); } } } else
		 * if(cmd.equals("logout internet")) {
		 * 
		 * } }
		 */
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
