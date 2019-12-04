package com.johnnie.pcapanalyzer;

import java.awt.EventQueue;
import java.io.File;

import javax.swing.JFrame;

import com.johnnie.pcapanalyzer.ui.MainFrame;
import com.johnnie.pcapanalyzer.utils.Constant;
import com.johnnie.pcapanalyzer.utils.FileUtils;

/**
 * 程序入口
 * @author johnnie
 * @time 2015年12月13
 */
public class PcapAnalyzer {

	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					// 创建 log
					FileUtils.createDir(Constant.LOG_DIR);
					File recent_log = new File(Constant.LOG_RECENT_FILE);
					if (!recent_log.exists()) {
						FileUtils.createEmpFile(Constant.LOG_RECENT_FILE);
					}
					
					// 启动主窗口
					new MainFrame().setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
		
	}
	
}
