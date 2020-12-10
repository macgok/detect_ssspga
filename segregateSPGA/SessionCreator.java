/**
 * 
 */
package segregateSPGA;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;

import segregateSPGA.dataType.Session;
import segregateSPGA.dataType.TCPFlow;
import segregateSPGA.utilities.Constants;
import segregateSPGA.utilities.FileHandler;
import segregateSPGA.utilities.Utilities;

/**
 * @author gokul
 * @since 15 May 2020
 */
public class SessionCreator {
	/***
	 * Get the total number of sessions. <br>
	 */
	public static long getTotalSessions(HashMap<String, ArrayList<Session>> hashMap) {
		long count = 0;

		for (String ip : hashMap.keySet()) {
			ArrayList<Session> sList = hashMap.get(ip);
			count += sList.size();
		}

		return count;
	}

	/***
	 * Write the number of sessions for different session gaps. <br>
	 * 
	 * @param limits
	 * @param flows
	 * @param outFilename
	 */
	public static void writeSessionCount(long limits[], ArrayList<TCPFlow> flows, String outFilename) {
		long sessionGap = limits[0];
		long endSessionGap = limits[1];
		long gapIncrement = limits[2]; // in seconds

		int maxSessions = flows.size();

		Constants.SESSION_GAP_INTERVAL = Long.MAX_VALUE;
		int minSessions = SessionCreator.getAttackers(flows).size();

		PrintWriter file = FileHandler.newFile(outFilename);

		while (true) {
			Constants.SESSION_GAP_INTERVAL = sessionGap;
			HashMap<String, ArrayList<Session>> attackers = SessionCreator.getAttackers(flows);
			long currSessionCnt = SessionCreator.getTotalSessions(attackers);

			double percent = (double) currSessionCnt / (double) maxSessions;
			String percentStr = Double.toString(percent);

			file.println(sessionGap + "," + percentStr);

			if (sessionGap >= endSessionGap || currSessionCnt <= minSessions) {
				break;
			}

			sessionGap += gapIncrement;
		}

		file.close();
	}

	/***
	 * Take a new TCP flow and insert into the right session. <br>
	 * Let x1 be the time when the last packet arrived/send in the previous TCP flow
	 * of the same IP. <br>
	 * Let x2 be the time when the first packet of the new TCP flow arrived. <br>
	 * Take the difference x=x2-x1. <br>
	 * If x > maximum session gap interval, then add to a new session. <br>
	 * Else, add in the previous session. <br>
	 * 
	 */
	public static HashMap<String, ArrayList<Session>> getAttackers(ArrayList<TCPFlow> flows) {
		HashMap<String, ArrayList<Session>> hashMap = new HashMap<String, ArrayList<Session>>();

		for (TCPFlow flow : flows) {
			String ip = flow.srcIP;

			if (hashMap.containsKey(ip)) {
				ArrayList<Session> sessions = hashMap.get(ip);
				int lstSessionIndex = sessions.size() - 1;
				Session lstSession = sessions.get(lstSessionIndex);

				int lstFlowIndex = lstSession.flows.size() - 1;
				TCPFlow lstSessionFlow = lstSession.flows.get(lstFlowIndex);

				if (((flow.startTime - lstSessionFlow.endTime) > Constants.SESSION_GAP_INTERVAL)) {
					Session newSession = new Session(flow);
					sessions.add(newSession);
				} else {
					lstSession.flows.add(flow);
				}
			} else {
				Session session = new Session(flow);
				ArrayList<Session> newSessions = new ArrayList<Session>();
				newSessions.add(session);
				hashMap.put(ip, newSessions);
			}
		}

		return hashMap;
	}

	/***
	 * Merge the sessions to form individual attackers. <br>
	 * 
	 * @param mapSessions
	 * @return
	 */
	public static HashMap<String, ArrayList<Session>> mergeSessions(HashMap<String, ArrayList<Session>> mapSessions) {
		HashMap<String, ArrayList<Session>> output = new HashMap<String, ArrayList<Session>>();

		for (String ip : mapSessions.keySet()) {
			ArrayList<Session> sessions = mapSessions.get(ip);
			ArrayList<TCPFlow> flows = new ArrayList<TCPFlow>();
			sessions.forEach((s) -> flows.addAll(s.flows));
			ArrayList<Object> flowObjects = new ArrayList<Object>(flows);

			// only one session; directly add to the output
			if (sessions.size() <= 1) {
				output.put(ip, sessions);
				continue;
			}

			boolean status = Utilities.allSameField(flowObjects, new String[] { "remoteSSHVersion", "kex_algorithm",
					"key_algorithm", "outgoing_encr_algorithm", "outgoing_hash_algorithm", "outgoing_comp_algorithm" });
			if (status == true) {
				Session newSession = new Session(flows);
				ArrayList<Session> sAL = new ArrayList<Session>();
				sAL.add(newSession);
				output.put(ip, sAL);
			} else {
				output.put(ip, sessions);
			}
		}

		return output;
	}

}
