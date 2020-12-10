/**
 * 
 */
package segregateSPGA;

import java.util.ArrayList;
import java.util.HashMap;

import segregateSPGA.dataType.Session;
import segregateSPGA.dataType.TCPFlow;
import segregateSPGA.dataType.UserAccount;
import segregateSPGA.utilities.Constants;
import segregateSPGA.utilities.Helper;

/**
 * @author gokul
 * 
 *         Segregate the password-guessing attacks into fast and stealthy ones.
 *         <br>
 */
public class StealthySessions {
	public static final int UNDETECTED = 0;
	public static final int DETECTED = 1;
	public static final int BLOCKED = 2;
	public static final int SUCCESS = 3;

	/***
	 * Implements the algorithms found in the security tools (IDS: fail2ban,
	 * DenyHosts, SSHblock, sshdfilter and SSHGuard) <br>
	 * Let X be the maximum number of retries (BF_Constants.MAX_RETRIES) <br>
	 * If X has occurred within Y (BF_Constants.DURATION) duration, then the attack
	 * is detected. <br>
	 * Count the number of logins (say Z) in the given blocking period. <br>
	 * 
	 * @param failedUserAccounts
	 * @return
	 */
	public static int[] checkSecurityToolAlgo1(ArrayList<UserAccount> failedUserAccounts) {
		long blockEnd = -1;
		int maxIndexInForLoop = failedUserAccounts.size() - Constants.MAX_RETRIES;
		UserAccount uauList[] = new UserAccount[Constants.MAX_RETRIES];
		int entries = uauList.length;
		int i = 0;
		int[] count = new int[] { 0, 0, 0 };

		for (; i <= maxIndexInForLoop; i++) {
			for (int j = 0; j < entries; j++) {
				uauList[j] = failedUserAccounts.get(i + j);
			}

			long firstTS = uauList[0].dateTime;
			if (firstTS <= blockEnd) {
				count[BLOCKED]++;
			} else {
				long lastTS = uauList[entries - 1].dateTime;
				long duration = lastTS - firstTS;

				if (duration <= Constants.DURATION) {
					count[DETECTED] += entries;
					blockEnd = lastTS + Constants.BAN_TIME;
					i += Constants.MAX_RETRIES - 1; // another +1 is done by the for loop
				} else {
					count[UNDETECTED]++;
				}
			}
		}

		for (; i < failedUserAccounts.size(); i++) {
			long ts = failedUserAccounts.get(i).dateTime;
			if (ts <= blockEnd) {
				count[BLOCKED]++;
			} else {
				count[UNDETECTED]++;
			}
		}

		return count;
	}

	/***
	 * Check detection algorithm in each session.
	 *
	 * @param session
	 * @return
	 */
	public static boolean isStealthySession(Session session) {
		ArrayList<TCPFlow> flows = session.flows;
		ArrayList<UserAccount> failedUserAccounts = new ArrayList<UserAccount>();
		flows.forEach((tcpFlow) -> failedUserAccounts
				.addAll(Helper.getUserAttempts(tcpFlow.accounts, Helper.ALL_ATTEMPTS_WITHOUT_NONE)));

		int[] countUA = checkSecurityToolAlgo1(failedUserAccounts);

		int cntDetected = countUA[DETECTED];

		// IDS Rule
		if (cntDetected == 0) {
			return true;
		} else {
			return false;
		}
	}

	/***
	 * Segregate the attacks.
	 * 
	 * @param
	 * @return
	 */
	public static HashMap<String, ArrayList<Session>> separateLoginAttempts(
			HashMap<String, ArrayList<Session>> attackers) {
		HashMap<String, ArrayList<Session>> mapMap = new HashMap<String, ArrayList<Session>>();

		for (String ip : attackers.keySet()) {
			ArrayList<Session> sessions = attackers.get(ip);

			// Errors: no login attempts, bad packet length

			ArrayList<TCPFlow> flows = new ArrayList<TCPFlow>();
			sessions.forEach((session) -> flows.addAll(session.flows));
			ArrayList<UserAccount> userAccounts = new ArrayList<UserAccount>();
			flows.forEach(
					(flow) -> userAccounts.addAll(Helper.getUserAttempts(flow.accounts, Helper.ALL_ATTEMPTS_WITHOUT_NONE)));

			// Scanners
			int uaSize = userAccounts.size();
			if (uaSize == 0) {
				continue;
			}

			// Success sessions
			userAccounts.clear();
			flows.forEach((flow) -> userAccounts.addAll(Helper.getUserAttempts(flow.accounts, Helper.SUCCESS_ATTEMPTS)));
			int uaSuccessSize = userAccounts.size();
			if (uaSize == uaSuccessSize) {
				continue;
			}

			// Process all the sessions
			ArrayList<Session> stealthSessions = new ArrayList<Session>();
			for (Session session : sessions) {
				userAccounts.clear();
				session.flows.forEach(
						(flow) -> userAccounts.addAll(Helper.getUserAttempts(flow.accounts, Helper.ALL_ATTEMPTS_WITHOUT_NONE)));
				int attempts = userAccounts.size();

				// Success session
				userAccounts.clear();
				session.flows
						.forEach((flow) -> userAccounts.addAll(Helper.getUserAttempts(flow.accounts, Helper.SUCCESS_ATTEMPTS)));
				int successAttempts = userAccounts.size();
				if (attempts == successAttempts) {
					continue;
				}

				// Check if stealthy
				boolean isStealthy = isStealthySession(session);
				if (isStealthy) {
					stealthSessions.add(session);
				}
			}

			if (stealthSessions.isEmpty() == false)
				mapMap.put(ip, stealthSessions);
		}

		return mapMap;
	}
}
