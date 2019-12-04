package com.johnnie.pcapanalyzer.utils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 文件操作工具类
 * @author johnnie
 */
public class FileUtils {
	
	private FileUtils(){}
	
	/**
	 * 将一条数据写入文件
	 * @param line 数据
	 * @param filepath 被写入的文件路径
	 * @param append 是否追加数据
	 * @return flag 写入是否成功
	 */
	public static boolean writeLineToFile(String line, File file, boolean append){
		boolean flag = true;
		try {
			FileWriter fw = new FileWriter(file, append);
			fw.write(line + "\n");
			fw.flush();
			fw.close();
		} catch (IOException e) {
			e.printStackTrace();
			flag = false;
		}
		
		return flag;
	}
	
	/**
	 * 将一条数据写入文件
	 * @param line 数据
	 * @param filepath 文件路径
	 * @param append 是否追加数据
	 */
	public static boolean writeLineToFile(String line, String filepath, boolean append){
		File file = new File(filepath);
		return writeLineToFile(line, file, append);
	}
	
	/**
	 * 写入多行数据，并未每一条数据自动补上换行符
	 * @param lines
	 * @param filepath
	 * @param append
	 * @return flag 
	 */
	public static boolean writeLinesToFile(String[] lines, String filepath, boolean append){
		boolean flag = true;
		try {
			File file = new File(filepath);
			FileWriter fw = new FileWriter(file, append);
			for(String line : lines){
				line += "\n";
				fw.write(line);
			}
			fw.flush();
			fw.close();
		} catch (IOException e) {
			e.printStackTrace();
			flag = false;
		}
		
		return flag;
	}
	
	/**
	 * 若文件夹不存在，则创建文件夹
	 * @param dirpath	目录路径
	 * @return flag		目录创建是否成功的标志
	 */
	public static boolean createDir(String dirpath){
		boolean flag = false;
		File file = new File(dirpath);
		if(!file.exists()){						// 判断该目录是否存在
			file.mkdirs();
			flag = true;
		} 
		
		return flag;
	}
	
	/**
	 * 删除单个文件
	 * @param filepath : 被删除文件的文件名	  
	 * @return		   : 单个文件删除成功返回true，否则返回false
	 */
	public static boolean deleteFile(String filepath){
		boolean flag = false;
		File file = new File(filepath);
		// 路径为文件且不为空时，删除
		if(file.isFile() && file.exists()){
			file.delete();
			flag = true;
		}
		return flag;
	}
	
	/**
	 * 删除目录（文件夹）以及目录下的文件
	 * @param path	   : 被删除目录的文件路径
	 * @return		   : 目录删除成功返回true，否则返回false
	 */
	private static boolean deleteDirectory(String path){
		boolean flag = false;

		//如果 path 不以文件分隔符结尾，自动添加文件分隔符
		if(!path.endsWith(File.separator)){
			path = path + File.separator;
		}
		File dirFile = new File(path);

		// 如果 dir 对应的文件不存在，或者不是一个目录，则退出 
		if(!dirFile.exists() || !dirFile.isDirectory()){
			return false;
		}
		flag = true;

		// 删除文件夹下的所有文件(包括子目录)
		File[] files = dirFile.listFiles();
		for(int i = 0; i < files.length; i ++){
			// 删除子文件
			if(files[i].isFile()){
				flag = deleteFile(files[i].getAbsolutePath());
				if(!flag){
					break;
				}
			} else{
				flag = deleteDirectory(files[i].getAbsolutePath());
				if(!flag){
					break;
				}
			}
		}
		if(!flag){
			return false;
		}

		// 删除当前目录
		if(dirFile.delete()){
			return true;
		} else{
			return false;
		}

	}
	
	/**
	 * 通用的文件夹或文件删除方法，直接调用此方法，即可实现删除文件夹或文件，包括文件夹下的所有
	 * 文件
	 * @param path	   : 要删除的目录或文件
	 * @return		   : 删除成功返回 true，否则返回 false。
	 */
	public static boolean deleteFolder(String path){
		boolean flag = false;
		File file = new File(path);
		// 判断文件或目录是否存在
		if(!file.exists()){
			return flag;
		} else{
			// 判断是否为文件
			if(file.isFile()){		// 为文件时调用删除文件的方法
				return deleteFile(path);
			} else{					// 为目录时调用删除目录方法
				return deleteDirectory(path);
			}
		}
	}
	
	/**
	 * 关闭输入输出流
	 * @param is
	 * @param os
	 */
	public static void closeStream(InputStream is, OutputStream os) {
		if(is != null){
			try {
				is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		if(os != null){
			try {
				os.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	/**
	 * 打开指定路径的磁盘窗口
	 * @param path 文件路径 路径必须是形如 C:\Test\ 的形式，必须是右斜杠
	 */
	public static void openWindow(String path){
		Runtime runtime = Runtime.getRuntime();
		try {
			Process process = runtime.exec("cmd /c start explorer " + path);
			int exitCode = process.waitFor();
			if(exitCode == 0){
				// success
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 创建一个空文件
	 * @param pathname
	 */
	public static void createEmpFile (String pathname) {
		File file = new File(pathname);
		if (file.exists()) {
			deleteFile(pathname);
		}
		
		try {
			file.createNewFile();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * 判断文件是否存在
	 * @param file
	 */
	public static boolean isFileEmpty(File file) {
		if (file == null || file.length() < 0) {
			return false;
		} else {
			return true;
		}
	}
	
}
