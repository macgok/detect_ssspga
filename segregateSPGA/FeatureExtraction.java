package segregateSPGA;

import java.util.ArrayList;
import java.util.Collections;
import java.util.StringJoiner;

import segregateSPGA.dataType.Session;
import segregateSPGA.dataType.TCPFlow;
import segregateSPGA.dataType.UserAccount;
import segregateSPGA.utilities.Constants;
import segregateSPGA.utilities.Entropy;
import segregateSPGA.utilities.Helper;

public class FeatureExtraction {
	public static final int ONE_ATTEMPT = 0;
	public static final int ERROR_CODE1 = -1;

	/***
	 * Find shannon entropy for a list of user accounts. <br>
	 * 
	 * @param accounts
	 * @return -1 or (0 to 1)
	 */
	public static double getEntropy(ArrayList<UserAccount> accounts) {
		int size = accounts.size();
		if (size <= 0)
			return ERROR_CODE1;

		ArrayList<Double> proportions = new ArrayList<Double>();

		ArrayList<UserAccount> uniqAccounts = Helper.getUniqueLogins(accounts);

		for (int i = 0; i < uniqAccounts.size(); i++) {
			UserAccount ua = uniqAccounts.get(i);
			int occurenceCnt = Helper.getNoOfOccurences(ua, accounts);
			double proportion = (double) occurenceCnt / (double) size;
			proportions.add(proportion);
		}

		double entropy = Entropy.getNormEntropy(proportions, accounts.size());

		return entropy;
	}

	/***
	 * Get the repetition metric. <br>
	 * 
	 * @param flows
	 * @return -1, -2, [0-1]
	 */
	public static double getRM(ArrayList<TCPFlow> flows) {
		ArrayList<UserAccount> allAccounts = new ArrayList<UserAccount>();
		flows.forEach((flow) -> allAccounts.addAll(flow.accounts));
		ArrayList<UserAccount> noNoneAccts = Helper.getUserAttempts(allAccounts, Helper.ALL_ATTEMPTS_WITHOUT_NONE);

		if (noNoneAccts.size() == 0)
			return ERROR_CODE1;
		else if (noNoneAccts.size() == 1)
			return ONE_ATTEMPT;

		double e = getEntropy(noNoneAccts);
		if (e == -1) // error
			return ERROR_CODE1;
		else if (e >= 1) // sometimes double arithmetic returns 1.000000000002
			return 0;
		else
			return 1 - e;
	}

	/***
	 * The first TCP flow in a session should be a scanning flow. <br>
	 * 
	 * @param session
	 * @return
	 */
	public static boolean isFirstFlowScanner(Session session) {
		if (session.flows.size() == 0) {
			return false;
		} else {
			TCPFlow flow = session.flows.get(0);
			if (flow.accounts.size() == 0) {
				return true;
			} else {
				return false;
			}
		}
	}

	/***
	 * Get the interval between scanning and login attempt. <br>
	 * 
	 * @param session
	 * @return
	 */
	public static ArrayList<Long> getDurations(Session session) {
		ArrayList<Long> durations = new ArrayList<Long>();

		boolean isFirstFlowScan = isFirstFlowScanner(session);
		if (isFirstFlowScan == true) {
			long t_scan = -1, t_la = -1;
			for (TCPFlow flow : session.flows) {
				if (flow.accounts.size() == 0) { // Check for scanners
					if (t_scan == -1) {
						t_scan = flow.startTime;
					}
				} else {
					// First, scan flow should happen. Hence, t_scan should not be equal to -1.
					if (t_scan != -1 && t_la == -1) {
						t_la = flow.startTime;
					}
				}

				if (t_scan != -1 && t_la != -1) {
					long duration = t_la - t_scan;
					durations.add(duration);
					t_scan = t_la = -1;
				}
			}
		}

		return durations;
	}

	/***
	 * Get the interval between scanning and login attempt. <br>
	 * 
	 * @param session
	 * @return if no duration, empty string.
	 */
	public static String getDuration(Session session) {
		ArrayList<Long> durations = getDurations(session);

		String duration = ""; // durations.size() = 0
		if (durations.size() >= 1) {
			Collections.sort(durations);
			duration = Long.toString(durations.get(0));
		}

		return duration;
	}

	/***
	 * Minimum time difference between TCP flows. <br>
	 * 
	 * @param session
	 * @return -1 if the session has only scanners.
	 */
	public static long getMinSuccessiveFlowInterval(Session session) {
		// Discard the scanners
		ArrayList<TCPFlow> uaFlows = new ArrayList<>();
		for (TCPFlow flow : session.flows) {
			int uaCount = flow.accounts.size();
			if (uaCount > 0) {
				uaFlows.add(flow);
			}
		}

		// The session has only scanners.
		if (uaFlows.size() == 0) {
			return -1;
		} else {
			long smallestDiffTime = Constants.DURATION;
			for (int i = 0; i < uaFlows.size() - 1; i++) {
				long differenceTime = uaFlows.get(i + 1).startTime - uaFlows.get(i).startTime;				
				if (differenceTime <= Constants.DURATION && differenceTime >= 0) {
					if (differenceTime < smallestDiffTime) {
						smallestDiffTime = differenceTime;
					}
				}
			}

			return smallestDiffTime;
		}
	}

	/***
	 * Get the data set from the list of sessions. <br>
	 * 
	 * @param sessions
	 * @return
	 */
	public static ArrayList<String> getDataset(ArrayList<Session> sessions) {
		String header = "f1,f2,f3,f4";

		ArrayList<String> dataset = new ArrayList<String>();
		dataset.add(header);

		for (Session session : sessions) {
			StringJoiner joiner = new StringJoiner(",", "", "");

			// Number of login attempts
			ArrayList<UserAccount> userAccounts = new ArrayList<UserAccount>();
			session.flows.forEach((flow) -> userAccounts
					.addAll(Helper.getUserAttempts(flow.accounts, Helper.ALL_ATTEMPTS_WITHOUT_NONE)));
			int attempts = userAccounts.size();

			// Repeated logins
			double rm = getRM(session.flows);

			// Scanning
			String scanLAInterval = getDuration(session);

			// Bandwidth
			long bw = getMinSuccessiveFlowInterval(session);

			// Add to the csv file
			joiner.add(Integer.toString(attempts));
			joiner.add(Double.toString(rm));
			joiner.add(scanLAInterval);
			joiner.add(Long.toString(bw));

			dataset.add(joiner.toString());
		}

		return dataset;
	}
}
