/**
 * 
 */
package segregateSPGA.hailmarySGPA;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import segregateSPGA.FeatureExtraction;
import segregateSPGA.SessionCreator;
import segregateSPGA.StealthySessions;
import segregateSPGA.dataType.Session;
import segregateSPGA.dataType.TCPFlow;
import segregateSPGA.dataType.UserAccount;
import segregateSPGA.utilities.Constants;
import segregateSPGA.utilities.FileHandler;
import segregateSPGA.utilities.Helper;

/**
 * @author gokul
 *
 */
public class ProcessHailMaryLogs2012 {
	// Filenames
	static final String DIR_HAILMARY_DATASET_2008 = FileHandler.COMMON_DIRECTORY
			+ "2008-2019_Dataset_HailMary_Botnet//2008-2012_Dataset/";
	static final String FILE_PREFIX = "bigauthlog_";
	static final String FILE_SUFFIX_1_20081119 = "20081119";
	static final String FILE_SUFFIX_2_20090407 = "20090407";
	static final String FILE_SUFFIX_3_20090930 = "20090930";
	static final String FILE_SUFFIX_4_20091028 = "20091028";
	static final String FILE_SUFFIX_5_20100617 = "20100617";
	static final String FILE_SUFFIX_6_20111023 = "20111023";
	static final String FILE_SUFFIX_7_20111103 = "20111103";
	static final String FILE_SUFFIX_8_20120401 = "20120401";
	static final String FILE_SUFFIXES[] = { FILE_SUFFIX_1_20081119, FILE_SUFFIX_2_20090407, FILE_SUFFIX_3_20090930,
			FILE_SUFFIX_4_20091028, FILE_SUFFIX_5_20100617, FILE_SUFFIX_6_20111023, FILE_SUFFIX_7_20111103,
			FILE_SUFFIX_8_20120401 };

	// Regex Expressions
	static final String DATETIME_REGEX = "(^[a-zA-Z]{3} *[0-3]?[0-9] [0-2]?[0-9]:[0-5]?[0-9]:[0-5]?[0-9])";
	static final String AUTH_ERROR_REGEX = DATETIME_REGEX
			+ ".*?authentication error for (illegal user )?(.*?) from (.*)";

	static final String AUTH_PASSWORD = "password";

	/***
	 * Convert string date to long. <br>
	 * 
	 * @param line
	 * @return time in seconds
	 */
	public static long getDateTime(String line) {
		DateFormat formatter;

		try {
			formatter = new SimpleDateFormat("yyyy MMM d H:m:s");// 2000 Jan 24 23:34:33
			Date date = formatter.parse(line);
			return date.getTime() / 1000;
		} catch (ParseException e) {
			e.printStackTrace();
		}

		return -1;
	}

	/***
	 * Get an arraylist of TCPFlow objects.
	 * 
	 * @param loginAttempts
	 * @return
	 */
	public static ArrayList<TCPFlow> getFlows() {
		Pattern pattern = Pattern.compile(AUTH_ERROR_REGEX);
		ArrayList<TCPFlow> flows = new ArrayList<TCPFlow>();

		for (String filenameSuffix : FILE_SUFFIXES) {
			String filename = DIR_HAILMARY_DATASET_2008 + FILE_PREFIX + filenameSuffix + ".txt";
			System.out.println(filename);

			ArrayList<String> lines = FileHandler.readFile(filename);
			for (String line : lines) {
				Matcher m = pattern.matcher(line);
				if (m.matches()) {
					String dateTime = filenameSuffix.substring(0, 4) + " " + m.group(1);
					long ts = ProcessHailMaryLogs2012.getDateTime(dateTime);

					TCPFlow flow = new TCPFlow();
					flow.srcIP = m.group(4);
					flow.startTime = flow.endTime = ts;

					UserAccount userAcc = new UserAccount();
					userAcc.type = AUTH_PASSWORD;
					userAcc.username = m.group(3);
					userAcc.password = "";
					userAcc.dateTime = ts;
					userAcc.isSucceeded = false;

					flow.accounts.add(userAcc);

					flows.add(flow);
				}
			}
		}

		return flows;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		ArrayList<TCPFlow> flows = ProcessHailMaryLogs2012.getFlows();

		Constants.SESSION_GAP_INTERVAL = Long.MAX_VALUE;
		HashMap<String, ArrayList<Session>> mapSessions = SessionCreator.getAttackers(flows);

		HashMap<String, ArrayList<Session>> mapStealthySessions = StealthySessions.separateLoginAttempts(mapSessions);

		ArrayList<Session> allSessions = new ArrayList<Session>();
		mapStealthySessions.forEach((k, v) -> allSessions.addAll(v));

		if (Helper.DEBUG) {
			FileHandler.write("/home/gokul/Documents/hailmary2012_flows", new ArrayList<Object>(flows), false, "\n");
			FileHandler.writeHashMap(mapSessions, "/home/gokul/Documents/hailmary2012_sessions", (short) 1);
			FileHandler.writeHashMap(mapStealthySessions, "/home/gokul/Documents/hailmary2012_stealthy_sessions",
					(short) 1);
			FileHandler.write("/home/gokul/Documents/hailmary2012_stealthy_sessions1",
					new ArrayList<Object>(allSessions), false, "\n");
		}
		
		String filename = "/home/gokul/Documents/dataset_hailmary2012.csv";
		ArrayList<String> dataset = FeatureExtraction.getDataset(allSessions);
		FileHandler.write(filename, new ArrayList<Object>(dataset), false, "\n");
	}
}
