package com.johnnie.pcapanalyzer.ui;

import java.util.List;

import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;

import com.johnnie.pcapanalyzer.utils.LogUtils;
import com.johnnie.pcapanalyzer.utils.WindowUtils;

public class ParserRsFrame extends BaseFrame {

	private static final long serialVersionUID = 1L;

	private static final int FRAME_WIDTH = 400;
	private static final int FRAME_HEIGHT = 300;

	private JTable table;
	private List<String[]> datas;
	
	private ParserRsFrame(List<String[]> datas) {
		this.datas = datas;
		initViews();
		initEvents();
	}
	
	public static void start (List<String[]> datas) {
		new ParserRsFrame(datas);
	}
	

	@Override
	public void initViews() {
		// 表头
//		String[] tab_headers = new String[]{ "Protocol", "srcIP", "srcPort", 
//											"desIP", "desPort", "Option"};
		String[] tab_headers = new String[]{"Pcap会话提取结果："};
		Object[][] rowsValue = getRowDatas();
		TableModel model = new DefaultTableModel(rowsValue, tab_headers);
		table = new JTable(model);
		table.getTableHeader().setReorderingAllowed(false);		// 设置不可整列移动
		table.getTableHeader().setResizingAllowed(true);		// 设置可以修改列宽
		JScrollPane panel = new JScrollPane(table);

		// 得到屏幕尺寸
		int screenWidth = WindowUtils.getScreenWidth();
		int screenHeight = WindowUtils.getScreenHeight();
		int x = (screenWidth - FRAME_WIDTH) / 2 + 100;		// x 轴位移
		int y = (screenHeight - FRAME_HEIGHT) / 2 + 100;	// y 轴位移

		this.setTitle(super.getTitle());
		this.setBounds(x, y, FRAME_WIDTH, FRAME_HEIGHT);
		this.setContentPane(panel);
		this.setResizable(false);								// 去掉窗体最大化
		this.setVisible(true);
	}

	/**
	 * 从 datas 中获取行数
	 * @return
	 */
	private Object[][] getRowDatas() {
		LogUtils.printObj("datas.size", datas.size());
		Object[][] rowsVal = new Object[datas.size()][1];
		for (int i = 0; i < datas.size(); i ++) {
			Object[] row = new Object[1];
			Object[] data = datas.get(i);
			String filename = (String) data[0];
			String filepath = (String) data[1];
			row[0] = filename;
			rowsVal[i] = row;
		}
		
		return rowsVal;
	}

	@Override
	public void initEvents() {

	}

}
