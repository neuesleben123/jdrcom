interface MessageListener {
	public void ReciveMessage(Message msg);
}

interface MessageAdapter {
	public void addMessageListener(MessageListener ml);
}

public class jdrcom_main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		if (args.length != 0) {
			CLI cli = new CLI(); // 命令行版
			cli.run(args);
//			if (false == cli.run(args)) {
//				System.out.println("遇到错误，程序结束");
//				return;
//			}
		} else {
			GUI gui = new GUI(); // 图形界面版
			gui.showMe();
		}
	}
}
