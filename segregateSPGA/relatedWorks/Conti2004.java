package segregateSPGA.relatedWorks;

import java.util.ArrayList;

import kippoHP_SGPA.ProcessKippoLogs;
import segregateSPGA.dataType.Session;
import segregateSPGA.dataType.TCPFlow;
import segregateSPGA.utilities.FileHandler;

/**
 * @author gokul
 * 
 *         Paper: Passive Visual Fingerprinting of Network Attack Tools
 */
public class Conti2004 {

	public static void main(String[] args) {
		ArrayList<Session> sessions = ProcessKippoLogs.getStealthySessions();
		ArrayList<TCPFlow> flows = new ArrayList<TCPFlow>();
		sessions.forEach((session) -> flows.addAll(session.flows));

		ArrayList<String> lines = new ArrayList<String>();
		lines.add("sIP,sPort,dIP,dPort");
		for (TCPFlow flow : flows) {
			long sIP = Utilities.ipToLong(flow.srcIP);
			long dIP = Utilities.ipToLong(flow.dstIP);
			lines.add(sIP + "," + flow.srcPort + "," + dIP + "," + flow.dstPort);
		}

		FileHandler.write("/home/gokul/Documents/dataset_conti2004.csv", new ArrayList<Object>(lines), false, "\n");
	}

}
