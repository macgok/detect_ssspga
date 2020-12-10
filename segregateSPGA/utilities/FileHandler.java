/**
 * 
 */
package segregateSPGA.utilities;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import segregateSPGA.dataType.Session;

/**
 * @author gokul
 *
 */
public class FileHandler {
	public final static String COMMON_DIRECTORY = "/home/gokul/Dropbox/Research/Datasets/";
	
	/***
	 * Create a new file.
	 * 
	 * @param filename
	 * @return if there is an exception, then return null.
	 */
	public static PrintWriter newFile(String filename) {
		try {
			FileWriter fileOutStrm = new FileWriter(filename, false);
			BufferedWriter bufWriter = new BufferedWriter(fileOutStrm);
			PrintWriter outWriter = new PrintWriter(bufWriter, true);
			return outWriter;
		} catch (IOException ex) {
			System.err.println(ex.getMessage());
		}

		return null;
	}

	/***
	 * Create a new directory if one doesn't exist.
	 *
	 * @param dirName name of the directory
	 * @return TRUE if creation was successful or a directory exists.
	 * @pre parent directories should exist
	 */
	public static boolean createDir(String dirName) {
		File dir = new File(dirName);
		if (dir.exists()) {
			return true;
		}
		return dir.mkdirs();
	}

	/***
	 * Compare based on an integer found in the filename. <br>
	 * Sort it in descending order. <br>
	 */
	public static Comparator<String> comparatorDescOrder = new Comparator<String>() {
		@Override
		public int compare(String s1, String s2) {
			int n1 = getIntValue(s1);
			int n2 = getIntValue(s2);
			return n2 - n1;
		}

		private int getIntValue(String filename) {
			Pattern p = Pattern.compile("[0-9]+");
			Matcher m = p.matcher(filename);

			if (m.find()) {
				String s = m.group();
				Integer i = Integer.valueOf(s);
				return i.intValue();
			}

			return 0;
		}
	};
	
	/***
	 * Get all filenames in a directory.
	 *
	 * @param dirName         the directory containing files
	 * @param absolute        if true, absolute filename is returned. <br>
	 *                        if false, relative filename is returned.
	 * @param targetSubString to search for a particular filename.
	 * @return a list of filenames (no sub-directories)
	 */
	public static ArrayList<String> getFilenames(String dirName, boolean absolute, String targetSubString) {
		File folder = new File(dirName);
		File[] listOfFiles = folder.listFiles();
		ArrayList<String> list = new ArrayList<String>();
		String filename = null;

		if (listOfFiles != null) {
			for (int i = 0; i < listOfFiles.length; i++) {
				if (listOfFiles[i].isFile()) {
					filename = listOfFiles[i].getName();
					if (filename.contains(targetSubString)) {
						if (absolute == true) {
							list.add(dirName + "/" + filename);
						} else {
							list.add(filename);
						}
					}
				}
			}
		}

		return list;
	}

	/***
	 * Get all filenames (not absolute path) in a directory. <br>
	 * All filenames are sorted. <br>
	 *
	 * @param dirName - the directory containing files
	 * @return a list of filenames (relative path)
	 */
	public static ArrayList<String> getRelFilenames(String dirName, String targetSubString,
			Comparator<String> comparator) {
		ArrayList<String> list = getFilenames(dirName, false, targetSubString);

		Collections.sort(list, comparator);

		return list;
	}

	/***
	 * Read the contents of a file.
	 *
	 * @param filename Absolute filename
	 * @return
	 */
	public static ArrayList<String> readFile(String filename) {
		ArrayList<String> aryList = new ArrayList<String>();

		try {
			FileReader fileInStrm = new FileReader(filename);
			BufferedReader inFile = new BufferedReader(fileInStrm);
			String inputLine;

			while ((inputLine = inFile.readLine()) != null) {
				aryList.add(inputLine);
			}

			inFile.close();
		} catch (Exception ex) {
			System.err.println(ex.getMessage());
		}

		return aryList;
	}

	/**
	 * Write to a file - A list is written to a file. <br>
	 * 
	 * @param filename
	 * @param msgs
	 */
	public static void write(String filename, ArrayList<Object> msgs, boolean append, String delimiter) {
		try {
			FileWriter fileOutStrm = new FileWriter(filename, append);
			BufferedWriter bufWriter = new BufferedWriter(fileOutStrm);
			PrintWriter outWriter = new PrintWriter(bufWriter, true);

			for (Object message : msgs) {
				outWriter.print(message + delimiter);
			}
			outWriter.close();
		} catch (Exception ex) {
			System.err.println(ex.getMessage());
		}
	}

	/**
	 * Write hashmap to a file. <br>
	 */
	public static void writeHashMap(HashMap<String, ArrayList<Session>> hashMap, String filename, short printType) {
		PrintWriter file = newFile(filename);

		for (String key : hashMap.keySet()) {
			ArrayList<Session> sessions = hashMap.get(key);
			file.println(key);

			StringBuffer buffer = new StringBuffer();
			sessions.forEach((a) -> buffer.append(a + "\n\n"));
			file.print(buffer.toString());

			file.println();
			file.println();
			file.println();
			file.println();
		}

		file.close();
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
