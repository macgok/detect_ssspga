/**
 * 
 */
package segregateSPGA.kippoHP_SGPA;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
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
import segregateSPGA.utilities.FileHandler;
import segregateSPGA.utilities.Helper;
import segregateSPGA.utilities.Utilities;

/**
 * @author gokul
 *
 */
public class ProcessKippoLogs {
	// Regex Constants
	public final static String COMMA = ",";
	public final static String CLOSE_BRACKET = "\\]";
	public final static String OPEN_BRACKET = "\\[";
	public final static String NUM = "\\d+";

	public final static String DATETIME_REGEX = "[0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+\\+[0-9]+";
	public final static String IP_ADDRESS = "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+";

	public final static String NEW_CONNECTION = "New connection: ";
	private final static String NEW_CONNECTION_REGEX = "(.*?) \\[kippo\\.core\\.ssh\\.HoneyPotSSHFactory\\] New connection: (.*?):(.*?) .*?session: (.*)\\]";

	public final static String SESSION_CONTEXT = COMMA + NUM + COMMA + IP_ADDRESS;
	public final static String HP_TRANSPORT_CONTEXT = DATETIME_REGEX + " " + OPEN_BRACKET + "HoneyPotTransport"
			+ SESSION_CONTEXT + CLOSE_BRACKET + ".*";

	public final static String SSH_VERSION_STRING = "Remote SSH version: ";
	public final static String SSH_VERSION_REGEX = "Remote SSH version: .*";
	public final static String SSH_KEX_STRING = "kex alg, key alg: ";
	public final static String SSH_KEX_REGEX = "kex alg, key alg: .*";
	public final static String SSH_OUTGOING_CRYPT_STRING = "outgoing: ";
	public final static String SSH_OUTGOING_CRYPT_REGEX = "outgoing: .*";

	public final static String LOGIN_AUTH_REGEX = "trying auth .*";
	public final static String LOGIN_AUTH_STRING = "trying auth ";
	public final static String LOGIN_CONTEXT1 = DATETIME_REGEX + " " + OPEN_BRACKET
			+ "SSHService ssh\\-userauth on HoneyPotTransport" + SESSION_CONTEXT + CLOSE_BRACKET + " .* trying auth .*";

	public final static String LOGIN_REGEX = " login attempt \\[.*/.*\\]";
	public final static String LOGIN_SUCCESS = "succeeded";
	public final static String LOGIN_CONTEXT = DATETIME_REGEX + " " + OPEN_BRACKET
			+ "SSHService ssh\\-userauth on HoneyPotTransport" + SESSION_CONTEXT + CLOSE_BRACKET + LOGIN_REGEX
			+ " (failed|" + LOGIN_SUCCESS + ")";

	public final static String CLOSE_CONNECTION = "connection lost";

	// Filenames
	public final static String KIPPO_LOG_DIRECTORY1 = FileHandler.COMMON_DIRECTORY + "Capture_2/Honeypot_Logs/Kippo_Logs_4May2017";
	public final static String KIPPO_LOG_DIRECTORY2 = FileHandler.COMMON_DIRECTORY + "Capture_2/Honeypot_Logs/Kippo_Logs_11May2017";
	public final static String KIPPO_LOG_DIRECTORY3 = FileHandler.COMMON_DIRECTORY
			+ "Capture_3/Honeypot_Logs_Analysis/kippo-logs-analysis-2Dec2017/log0";
	public final static String KIPPO_LOG_DIRECTORY4 = FileHandler.COMMON_DIRECTORY
			+ "Capture_3/Honeypot_Logs_Analysis/kippo-logs-analysis-2Dec2017/log1";
	public final static String KIPPO_LOG_DIRECTORY5 = FileHandler.COMMON_DIRECTORY
			+ "Capture_3/Honeypot_Logs/Kippo_Logs_10Jan2018/log";
	public final static String[] KIPPO_LOG_DIRECTORY = { KIPPO_LOG_DIRECTORY1, KIPPO_LOG_DIRECTORY2,
			KIPPO_LOG_DIRECTORY3, KIPPO_LOG_DIRECTORY4, KIPPO_LOG_DIRECTORY5 };

	/***
	 * Get the date and time. <br>
	 *
	 * Example: "2017-04-29 05:42:07+0530 [SSHService ssh-userauth on
	 * HoneyPotTransport,44953,52.222.2.234] login attempt [root/admin] succeeded"
	 * <br>
	 * Grabs "2017-04-29 05:42:07+0530" in the above line. <br>
	 * Converts the date and time to epoch (long). <br>
	 * 
	 * @param line a line in kippo log file
	 * @return epoch long integer
	 */
	public static long getDateTime(String line) {
		DateFormat formatter;
		String dateTime = Utilities.getMatchPattern(line, DATETIME_REGEX);

		try {
			formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
			Date date = formatter.parse(dateTime);
			return date.getTime() / 1000;
		} catch (ParseException e) {
			e.printStackTrace();
		}

		return -1;
	}

	/***
	 * The input line is a new connection, as shown below. <br>
	 *
	 * 2016-09-21 13:07:09+0530 [kippo.core.ssh.HoneyPotSSHFactory] New connection:
	 * 108.61.198.194:64167 (192.168.122.102:2222) [session: 16958] <br>
	 *
	 * This function will return the source IP, source port, destination IP,
	 * destination port, and session ID.
	 * 
	 * @param line line containing "New connection" string.
	 * @return if not a new connection, then returns null.
	 */
	public static TCPFlow parseNewConn(String line, String dstIP) {
		TCPFlow tcpFlow = null;
		Pattern pattern = Pattern.compile(ProcessKippoLogs.NEW_CONNECTION_REGEX);
		Matcher m = pattern.matcher(line);

		if (m.matches()) {
			tcpFlow = new TCPFlow();
			tcpFlow.srcIP = m.group(2);
			tcpFlow.srcPort = Integer.parseInt(m.group(3));
			tcpFlow.dstIP = dstIP;
			tcpFlow.dstPort = 22;
			tcpFlow.sessionID = Long.parseLong(m.group(4));
		}

		tcpFlow.startTime = getDateTime(line);
		tcpFlow.endTime = getDateTime(line);

		return tcpFlow;
	}

	/***
	 * Get the session ID. <br>
	 * Example: <br>
	 * "[SSHService ssh-userauth on HoneyPotTransport,45459,116.31.116.20]" <br>
	 * return 45459.
	 * 
	 * @param line a line in kippo log file
	 * @return
	 */
	public static long getSessionID(String line) {
		String matchLine = Utilities.getMatchPattern(line, SESSION_CONTEXT);
		if (matchLine != null) {
			String items[] = matchLine.split(",");
			return Long.parseLong(items[1]);
		} else
			return -1;
	}

	/***
	 * Get key-exchange algorithm and the signing algorithm.
	 * 
	 * @param line
	 * @return
	 */
	public static String[] getKeyAlgorithms(String line) {
		String kex = Utilities.getMatchPattern(line, SSH_KEX_REGEX, SSH_KEX_STRING);
		String[] algos = new String[2];
		algos = kex.split(" ");
		return algos;
	}

	/***
	 * Get the outgoing cryptographic algorithms. <br>
	 * 1) Encryption/Decryption algorithm. <br>
	 * 2) Integrity algorithm. <br>
	 * 3) Compression algorithm. <br>
	 *
	 * @param line a line in kippo log file
	 * @return
	 */
	static String[] getOutCryptAlgos(String line) {
		String tempCrypt = Utilities.getMatchPattern(line, SSH_OUTGOING_CRYPT_REGEX, SSH_OUTGOING_CRYPT_STRING);
		String[] cryptAlgos = new String[3];
		cryptAlgos = tempCrypt.split(" ");
		return cryptAlgos;
	}

	/***
	 * Transport Layer information. <br>
	 * 
	 * @param line
	 * @param flow
	 */
	public static void extractTransportInfo(String line, TCPFlow flow) {
		if (line.contains(SSH_VERSION_STRING))
			flow.remoteSSHVersion = Utilities.getMatchPattern(line, SSH_VERSION_REGEX, SSH_VERSION_STRING);
		else if (line.contains(SSH_KEX_STRING)) {
			String[] a = getKeyAlgorithms(line);
			flow.kex_algorithm = a[0];
			flow.key_algorithm = a[1];
		} else if (line.contains(SSH_OUTGOING_CRYPT_STRING)) {
			String[] a = getOutCryptAlgos(line);
			flow.outgoing_encr_algorithm = a[0];
			flow.outgoing_hash_algorithm = a[1];
			flow.outgoing_comp_algorithm = a[2];
		}
	}

	/***
	 * Get the username and password. <br>
	 * The line should look like <br>
	 * "2017-04-29 05:40:36+0530 [SSHService ssh-userauth on
	 * HoneyPotTransport,44951,116.31.116.20] login attempt [root/forintos] failed"
	 * <br>
	 * The regex will look for "login attempt [root/forintos]" <br>
	 * Returns "[root/forintos]". <br>
	 * 
	 * @param line a line in kippo log file
	 * @return
	 */
	private static String getUserPass(String line) {
		String userPass = Utilities.getMatchPattern(line, LOGIN_REGEX);
		if (userPass != null) {
			int startIndex = userPass.indexOf('[');
			int endIndex = userPass.indexOf(']');
			return userPass.substring(startIndex, endIndex + 1);
		} else
			return null;
	}

	/***
	 * Get the username from a line. <br>
	 * 
	 * @param line
	 * @return
	 */
	private static String getUsername(String line) {
		String userPass = getUserPass(line);
		if (userPass == null)
			return null;

		return userPass.substring(userPass.indexOf('[') + 1, userPass.indexOf('/'));
	}

	/***
	 * Get the password from a line. <br>
	 * 
	 * @param line
	 * @return
	 */
	private static String getPassword(String line) {
		String userPass = getUserPass(line);
		if (userPass == null)
			return null;

		return userPass.substring(userPass.indexOf('/') + 1, userPass.indexOf(']'));
	}

	/***
	 * Helper for login functionality. <br>
	 * 
	 * @param line
	 * @param flow
	 */
	private static void extractLoginInfo(String line, TCPFlow flow) {
		int count = flow.accounts.size();
		UserAccount userAccount = flow.accounts.get(count - 1);

		userAccount.username = getUsername(line);
		userAccount.password = getPassword(line);
		userAccount.dateTime = getDateTime(line);

		if (line.contains(LOGIN_SUCCESS)) {
			userAccount.isSucceeded = true;
			flow.successAttempts++;
		} else {
			userAccount.isSucceeded = false;
			flow.failedAttempts++;
		}
	}

	/***
	 * Compare based on an integer found in the filename. <br>
	 * Sort it in descending order. <br>
	 */
	public static Comparator<TCPFlow> comparatorTCPFlow = new Comparator<TCPFlow>() {
		@Override
		public int compare(TCPFlow flow1, TCPFlow flow2) {
			if (flow1.sessionID < flow2.sessionID)
				return -1;
			else if (flow1.sessionID > flow2.sessionID)
				return 1;
			else
				return 0;
		}
	};

	/***
	 * Get all the session information in an Arraylist. <br>
	 * 
	 * @param dir    directory containing all kippo log files
	 * @param osFile file having OS details
	 * @return arraylist
	 */
	public static ArrayList<TCPFlow> getAllFlows(String dir, String osFile, String dstIP) {
		ArrayList<String> files = FileHandler.getRelFilenames(dir, "kippo.log", FileHandler.comparatorDescOrder);
		HashMap<Long, TCPFlow> allFlows = new HashMap<Long, TCPFlow>();

		for (int fileNo = 0; fileNo < files.size(); fileNo++) {
			String primaryFile = dir + "/" + files.get(fileNo);
			ArrayList<String> primaryFileLines = FileHandler.readFile(primaryFile);
			System.out.println(primaryFile + "," + primaryFileLines.size());

			for (int i = 0; i < primaryFileLines.size(); i++) {
				String line = primaryFileLines.get(i);

				if (line.contains(NEW_CONNECTION)) {
					TCPFlow flow = parseNewConn(line, dstIP);
					allFlows.put(flow.sessionID, flow);
				} else {
					Long id = getSessionID(line);
					TCPFlow flow = allFlows.get(id);
					if (flow != null) {
						if (line.matches(HP_TRANSPORT_CONTEXT)) {
							extractTransportInfo(line, flow);
						} else if (line.matches(LOGIN_CONTEXT1)) {
							String auth = Utilities.getMatchPattern(line, LOGIN_AUTH_REGEX, LOGIN_AUTH_STRING);
							UserAccount ua = new UserAccount(auth);
							flow.accounts.add(ua);
						} else if (line.matches(LOGIN_CONTEXT)) {
							extractLoginInfo(line, flow);
						}

						// Update end time
						if (line.matches(HP_TRANSPORT_CONTEXT) && line.contains(CLOSE_CONNECTION)) {
							// do not update the end time
						} else {
							flow.endTime = getDateTime(line);
						}
					}
				}
			}
		}

		ArrayList<TCPFlow> list = new ArrayList<TCPFlow>();
		for (long key : allFlows.keySet()) {
			TCPFlow flow = allFlows.get(key);
			list.add(flow);
		}

		Collections.sort(list, ProcessKippoLogs.comparatorTCPFlow);

		return list;
	}

	/***
	 * List of legitimate IP addresses. <br>
	 */
	private static ArrayList<String> legitIPs = new ArrayList<String>() {
		private static final long serialVersionUID = 1L;
		{
			// tested from my house: Capture 3 only
			add("14.195.235.77");
			add("14.195.228.182");
			add("14.195.224.60");
			add("14.195.237.98");
			add("14.195.230.151");
			add("14.195.239.253");
			add("14.195.299.249");

			// tested from the server itself: Capture 3 only (after logging in from the
			// house)
			add("192.168.122.1");
		}
	};

	private static ArrayList<TCPFlow> removeLegitFlows(ArrayList<TCPFlow> flows) {
		ArrayList<TCPFlow> outputFlows = new ArrayList<TCPFlow>();

		for (TCPFlow flow : flows) {
			if (legitIPs.contains(flow.srcIP) == false) {
				outputFlows.add(flow);
			}
		}

		return outputFlows;
	}

	/***
	 * Common method may be used by many other packages.
	 * 
	 * @param datasetIndex
	 * @return
	 */
	public static ArrayList<TCPFlow> getAllMergedFlows() {
		ArrayList<TCPFlow> allFlows = new ArrayList<TCPFlow>();
		for (String filename : KIPPO_LOG_DIRECTORY) {
			ArrayList<TCPFlow> flows = getAllFlows(filename, "", "182.75.45.248");
			allFlows.addAll(flows);
		}

		return removeLegitFlows(allFlows);
	}

	/***
	 * Get the requested Sessions.
	 * 
	 * @return
	 */
	public static ArrayList<Session> getStealthySessions() {
		ArrayList<TCPFlow> flows = ProcessKippoLogs.getAllMergedFlows();
		HashMap<String, ArrayList<Session>> mapSessions = SessionCreator.getAttackers(flows);
		HashMap<String, ArrayList<Session>> mergedSessions = SessionCreator.mergeSessions(mapSessions);

		HashMap<String, ArrayList<Session>> mapStealthySessions = StealthySessions
				.separateLoginAttempts(mergedSessions);

		ArrayList<Session> allSessions = new ArrayList<Session>();
		mapStealthySessions.forEach((k, v) -> allSessions.addAll(v));

		if (Helper.DEBUG) {
			FileHandler.write("/home/gokul/Documents/kippo_flows", new ArrayList<Object>(flows), false, "\n");
			FileHandler.writeHashMap(mapSessions, "/home/gokul/Documents/kippo_sessions", (short) 1);
			FileHandler.writeHashMap(mergedSessions, "/home/gokul/Documents/kippo_merged_sessions", (short) 1);
			FileHandler.writeHashMap(mapStealthySessions, "/home/gokul/Documents/kippo_stealthy_sessions", (short) 1);
			FileHandler.write("/home/gokul/Documents/kippo_stealthy_sessions1", new ArrayList<Object>(allSessions),
					false, "\n");
		}

		return allSessions;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		ArrayList<Session> sessions = ProcessKippoLogs.getStealthySessions();
		String filename = "/home/gokul/Documents/dataset.csv";
		ArrayList<String> dataset = FeatureExtraction.getDataset(sessions);
		FileHandler.write(filename, new ArrayList<Object>(dataset), false, "\n");
	}
}
