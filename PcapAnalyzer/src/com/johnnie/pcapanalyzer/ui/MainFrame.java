package com.johnnie.pcapanalyzer.ui;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

import com.johnnie.pcapanalyzer.observer.PcapParserObserver;
import com.johnnie.pcapanalyzer.service.PcapParser;
import com.johnnie.pcapanalyzer.utils.Constant;
import com.johnnie.pcapanalyzer.utils.FileUtils;
import com.johnnie.pcapanalyzer.utils.LogUtils;
import com.johnnie.pcapanalyzer.utils.PropertiesUtils;
import com.johnnie.pcapanalyzer.utils.WindowUtils;

/**
 * ������
 * @author johnnie
 * @time 2015��12��13
 */
public class MainFrame extends BaseFrame implements ActionListener, Observer {

	private static final long serialVersionUID = 1L;
	private static final int FRAME_WIDTH = 500;			
	private static final int FRAME_HEIGHT = 200;
	private static final int RECENT_MAX_NUM = 5;
	
	private static final String COMMAND_IN = "ѡ��pcap�ļ�";
	private static final String COMMAND_OUT = "ѡ�����Ŀ¼";
	private static final String COMMAND_START = "�ְ�";
	
	private static final String COMMAND_OPEN = "  | Open Pcap";
	private static final String COMMAND_EXIT = "  | Exit";
	private static final String COMMAND_ABOUT = "  | About";
	private static final String COMMAND_OPEN_RECENT = "  | Reopen Closed File";
	private static final String COMMAND_CLEAR_ITEM = "  | Clear Items";
	
	private File pcap_file;									// ѡ��� pcap �ļ�
	private File out_dir;									// ���Ŀ¼

	private JPanel panel;
	
	private JTextField jtf_in;
	private JTextField jtf_out;
	
	private JButton jbtn_in;
	private JButton jbtn_out;
	private JButton jbtn_analysis;
	
	private JFileChooser chooser;
	
	private JMenu mFOpenRecent;
	private List<JMenuItem> mItemRecents;
	private JMenuItem mItemFORClear;
	
	private JMenuItem mItemFOpen;
	private JMenuItem mItemFExit;
	private JMenuItem mItemHAbout;
	
	public MainFrame() {
		super.setTitle("PcapAnalyzer");
		initViews();
		initEvents();
	}
	
	/**
	 * �ṩ���ⲿ����������ľ�̬����
	 */
	public static void start () {
		new MainFrame().setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}
	
	/**
	 * ��ʼ���¼�
	 */
	public void initEvents() {
		jbtn_in.addActionListener(this);
		jbtn_out.addActionListener(this);
		jbtn_analysis.addActionListener(this);

		mItemFOpen.addActionListener(this);
		mItemFExit.addActionListener(this);
		mItemFORClear.addActionListener(this);
		mItemHAbout.addActionListener(this);
		
		if (mItemRecents != null) {
			for (JMenuItem item : mItemRecents) {
				addRecentFileListener(item);
			}
		}
		
	}
	
	/**
	 * ������ļ���Ӽ����¼�
	 * @param item
	 */
	private void addRecentFileListener(JMenuItem item) {
		item.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				String path = item.getText().substring("  | ".length());
				LogUtils.printObj(path);
				pcap_file = new File(path);
				jtf_in.setText(path);
			}
		});
	}

	/**
	 * ��ʼ���������
	 */
	public void initViews() {
		panel = new JPanel();
		panel.setLayout(null);

		JLabel jl_in = new JLabel("pcap�ļ���");
		jl_in.setBounds(20, 10, 67, 15);
		panel.add(jl_in);

		JLabel jl_out = new JLabel("���Ŀ¼��");
		jl_out.setBounds(20, 55, 67, 15);
		panel.add(jl_out);

		jtf_in = new JTextField();
		jtf_in.setBounds(114, 7, 208, 23);
		panel.add(jtf_in);
		jtf_in.setColumns(10);

		jtf_out = new JTextField();
		jtf_out.setColumns(10);
		jtf_out.setBounds(114, 52, 208, 23);
		panel.add(jtf_out);

		jbtn_in = new JButton(COMMAND_IN);
		jbtn_in.setBounds(340, 6, 135, 23);
		panel.add(jbtn_in);

		jbtn_out = new JButton(COMMAND_OUT);
		jbtn_out.setBounds(340, 51, 135, 23);
		panel.add(jbtn_out);
		
		jbtn_analysis = new JButton(COMMAND_START);
		jbtn_analysis.setBounds(147, 95, 149, 23);
		panel.add(jbtn_analysis);

		// ����һ�� JFIleChooser ���󣬲�ָ�� C ��Ŀ¼ΪĬ���ļ��Ի���·��
		chooser = new JFileChooser("C:\\");
		
		initMenu();

		// �õ���Ļ�ߴ�
		int screenWidth = WindowUtils.getScreenWidth();
		int screenHeight = WindowUtils.getScreenHeight();
		int x = (screenWidth - FRAME_WIDTH) / 2;		// x ��λ��
		int y = (screenHeight - FRAME_HEIGHT) / 2;	// y ��λ��

		this.setTitle(super.getTitle());
		this.setBounds(x, y, FRAME_WIDTH, FRAME_HEIGHT);
		this.getContentPane().add(panel, BorderLayout.CENTER);
		this.setResizable(false);						// ȥ���������
		this.setVisible(true);
	}

	/**
	 * ��Ӳ˵����Ͳ˵�
	 */
	private void initMenu() {
		
		JMenuBar menuBar = new JMenuBar();
		this.setJMenuBar(menuBar);
		
		JMenu menuFile = new JMenu("File");
		menuBar.add(menuFile);
		
		mItemFOpen = new JMenuItem(COMMAND_OPEN);
		menuFile.add(mItemFOpen);
		
		mFOpenRecent = new JMenu("  | Open Recent");
		menuFile.add(mFOpenRecent);
		
		if (PropertiesUtils.isEmpty(Constant.LOG_RECENT_FILE)) {
			JMenuItem mItemFOROpen = new JMenuItem(COMMAND_OPEN_RECENT);
			mFOpenRecent.add(mItemFOROpen);
		} else {
			addRecentFItem();
		}
		
		mItemFORClear = new JMenuItem(COMMAND_CLEAR_ITEM);
		mFOpenRecent.add(mItemFORClear);
		
		mItemFExit = new JMenuItem(COMMAND_EXIT);
		menuFile.add(mItemFExit);
		
		JMenu menuHelp = new JMenu("Help");
		menuBar.add(menuHelp);
		
		mItemHAbout = new JMenuItem(COMMAND_ABOUT);
		menuHelp.add(mItemHAbout);
	}

	/**
	 * �������ļ��˵���
	 */
	private void addRecentFItem() {
		Object[] values = PropertiesUtils.getVals(Constant.LOG_RECENT_FILE);
		int size = RECENT_MAX_NUM;
		if (size > values.length) {
			size = values.length;
		}
		
		mItemRecents = new ArrayList<JMenuItem>();
		for (int i = 0; i < size; i ++) {
				JMenuItem item = new JMenuItem("  | " + (String) values[i]);
				mItemRecents.add(item);
		}
		
		for (JMenuItem item : mItemRecents) {
			mFOpenRecent.add(item);
		}
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		String command = e.getActionCommand();
		switch (command) {
		case COMMAND_IN:
			choosePcap();
			break;

		case COMMAND_OUT:
			chooseOutDir();
			break;
			
		case COMMAND_START:
			analysis();
			break;
		
		case COMMAND_OPEN:
			choosePcap();
			break;
		
		case COMMAND_CLEAR_ITEM:
			clearItems();
			break;
			
		case COMMAND_EXIT:
			exit();
			break;
			
		case COMMAND_ABOUT:
			about();
			break;
		
		}
	}

	/**
	 * �������ļ���¼
	 */
	private void clearItems() {
		LogUtils.printObj("���");
		mFOpenRecent.removeAll();
		JMenuItem mItemFOROpen = new JMenuItem(COMMAND_OPEN_RECENT);
		mFOpenRecent.add(mItemFOROpen);
		mFOpenRecent.add(mItemFORClear);

		PropertiesUtils.clear(Constant.LOG_RECENT_FILE);
		
	}

	/**
	 * ����
	 */
	private void about() {
		JOptionPane.showMessageDialog(null, Constant.ABOUT);
	}

	/**
	 * �˳�
	 */
	private void exit() {
		this.dispose();
		System.exit(0);
	}

	/**
	 * ��ȡTCP��UDP�Ự
	 */
	private void analysis() {
		
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					boolean flag = check();
					if (!flag) {
						JOptionPane.showMessageDialog(null, "��ѡ���ļ���Ŀ¼��","��ʾ", JOptionPane.ERROR_MESSAGE);
						return;
					}
					
					// ��ʼ���
					long startTime = System.currentTimeMillis();
					
					// �����ļ�����Ŀ¼
					String path = out_dir.getAbsolutePath();
					String tcp_path = path + "\\TCP\\";
					String udp_path = path + "\\UDP\\";
					String tcp_data_path = tcp_path + "���ݸ�����ȡ���\\";
					String udp_data_path = udp_path + "���ݸ�����ȡ���\\";
					FileUtils.createDir(tcp_path);
					FileUtils.createDir(udp_path);
					FileUtils.createDir(tcp_data_path);
					FileUtils.createDir(udp_data_path);
					
					path = null;
					tcp_path = null;
					udp_path = null;
					
					// ��������
					PcapParser pcapParser = new PcapParser(pcap_file, out_dir);
					PcapParserObserver observer = new PcapParserObserver();
					pcapParser.addObserver(observer);
					
					// �����⣬һ�������� pcap �ļ�������ʾ����ǰ�ɫ�ģ����ܹر�
//					Thread thread = new Thread(new Runnable() {
//						
//						@Override
//						public void run() {
//							MsgFrame msgFrame = MsgFrame.start("���ڽ��������Ժ�");
//							
//							try {
//								Thread.sleep(5000);
//							} catch (InterruptedException e) {
//								e.printStackTrace();
//							}
//							msgFrame.dispose();
//						}
//						
//					});
//					thread.start();
					
					pcapParser.parse();
					ParserRsFrame.start(observer.getDatas());
					
					// �������
					long endTime = System.currentTimeMillis();
					LogUtils.printTimeCost("Pcap�ļ������ʱ", (endTime - startTime));
					
				} catch (Exception e) {
					e.printStackTrace();
				}
			}

		});
	}

	/**
	 * ѡ�����Ŀ¼
	 */
	private void chooseOutDir() {
		int result;
		// ����ֻѡ��Ŀ¼
		chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		chooser.setApproveButtonText("ȷ��");
		chooser.setDialogTitle("��ѡ�����·��");
		result = chooser.showOpenDialog(this);

		if (result == JFileChooser.APPROVE_OPTION) {	// ����ȷ��
			out_dir = chooser.getSelectedFile();
			jtf_out.setText(out_dir.getAbsolutePath());
		}
	}

	/**
	 * ѡ�� Pcap �ļ�
	 */
	private void choosePcap() {
		int result;
		// ����ֻѡ���ļ�
		chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
		chooser.setApproveButtonText("ȷ��");
		chooser.setDialogTitle("��ѡ��pcap�ļ�");
		result = chooser.showOpenDialog(this);

		if (result == JFileChooser.APPROVE_OPTION) {	// ����ȷ��
			pcap_file = chooser.getSelectedFile();
			String filename = pcap_file.getName();
			String filepath = pcap_file.getAbsolutePath();
			jtf_in.setText(filepath);
			
			// ���� properties �ļ��в�����������ʱ����д��
			if (!PropertiesUtils.contains(Constant.LOG_RECENT_FILE, filename)) {
				PropertiesUtils.write(Constant.LOG_RECENT_FILE, filename, filepath);
				mFOpenRecent.removeAll();
				addRecentFItem();
				mFOpenRecent.add(mItemFORClear);
			}
			
		}
	}
	
	/**
	 * �������ĺϷ���
	 */
	private boolean check() {
		boolean flag = false;
		if (FileUtils.isFileEmpty(pcap_file)) {
			if (FileUtils.isFileEmpty(out_dir)) {
				flag = true;
			}
		}
		
		return flag;
	}

	@Override
	public void update(Observable o, Object arg) {
		
	}

}
