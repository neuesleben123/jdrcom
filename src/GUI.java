 
import java.awt.*;
//import java.awt.Event.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowListener;
import java.awt.event.WindowEvent;



 public class GUI  implements ActionListener , WindowListener
 {
	
	 TextField textFieldusername ;
	 TextField textFieldpwd ;

	   
		
	 public void paint()
	
	  {
		
		 
		 Frame f1 =new Frame();
		 f1.addWindowListener( new GUI());  // 关闭窗口
		 // Frame f2 =new Frame("lixiang");
		  
		   f1.setSize(100,200);
		  //f1.setSize(100,200);
		 //f1.setLayout(new GridLayout(5,5));
		 
		  
		  f1.setBackground(Color.YELLOW);
		   Button b1 =new Button("one");
		   Button b2 =new Button("two");
		   Button b3 =new Button("tree");
		   Button b4 =new Button("four");
		   Button b5 =new Button("five");
		   
		   BorderLayout e= new  BorderLayout(0,0);
		   
		   e.setHgap(5);
		   e.setVgap(5);
		   
		   f1.setLayout(e);
		   f1.setLayout(new FlowLayout());
		   
		   FlowLayout f=new FlowLayout(FlowLayout.RIGHT,10,20);
		   
		   f.setAlignment(FlowLayout.LEFT);
		   
		   
		   f1.add(b1,BorderLayout.EAST);
		   f1.add(b2,BorderLayout.NORTH);
		   f1.add(b3,BorderLayout.SOUTH);
		   f1.add(b4,BorderLayout.WEST);
		   f1.add(b5,BorderLayout.CENTER);
		   
		   //CardLayout card;
		   
		   b1.addActionListener(this);
		   b1.setActionCommand("one");
		   
		   
		   b2.addActionListener(this);
		   b2.setActionCommand("two"); 
		   
		  // b3.addActionListener(this);
		  
		   
		   Label labelusername=new Label("username",Label.LEFT);
		   f1.add(labelusername);
		   Label labelpwd=new Label("password",Label.LEFT);
		  
		   f1.add(labelusername);
		   f1.add(labelpwd);
		 textFieldusername=new TextField(15);
		   textFieldpwd=new TextField(15);
		   
		   textFieldpwd.setEchoChar('*');
		  // int a[][]={{0,0,1,1}};
		  f1.add(textFieldusername);
		  f1.add(textFieldpwd);
		  
		  
		   
		   //showStatus(getuser);
		   
		  f1.pack(); 
		  f1.setVisible(true);
		  //f2.setVisible(true);
		 
		
		
	  
	 }
	 public void windowClosing(WindowEvent e)
		{
		   System.exit(0);	
		}
	 public void  windowDeactivated(WindowEvent e){}
	 public void windowActivated(WindowEvent e){}
     public void windowOpened(WindowEvent e){}
	 public void windowIconified (WindowEvent e){}
	 public void  windowClosed(WindowEvent e){}
	 public void  windowDeiconified(WindowEvent e){}
	
	@Override
	public void actionPerformed(ActionEvent e) 
	{
		// TODO Auto-generated method stub
		
		 String  getuser1,getpwd2;
		 String cmd =e.getActionCommand();
		 if(cmd.equals("one"))
		 {
		   getuser1=textFieldusername.getText();
		   getpwd2=textFieldpwd.getText();	
		   
		   System.out.print(getuser1);
		 }
		 else 
		 {}
	}

}
