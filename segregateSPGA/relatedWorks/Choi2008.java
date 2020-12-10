package segregateSPGA.relatedWorks;

import java.util.ArrayList;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;

import segregateSPGA.kippoHP_SGPA.ProcessKippoLogs;
import segregateSPGA.dataType.Session;
import segregateSPGA.dataType.TCPFlow;
import segregateSPGA.utilities.FileHandler;

/**
 * @author gokul
 * 
 *         Paper: Fast detection and visualization of network attacks on
 *         parallel coordinates
 */
public class Choi2008 {
	/***
	 * Find the average packet length of all the packets in the pcap file. <br>
	 * 
	 * @param filename
	 * @return -1 on error.
	 */
	public static double getAveragePktLen(String filename) {
		Pcap pcap = Pcap.openOffline(filename, new StringBuilder());
		if (pcap == null) {
			return -1;
		}

		PcapPacket packet = new PcapPacket(JMemory.POINTER);
		int count = 0;
		long sum = 0;
		while (pcap.nextEx(packet) == Pcap.NEXT_EX_OK) {
			count++;
			sum += packet.size();
		}

		pcap.close();

		return (double) sum / (double) count;
	}

	public static void main(String[] args) {
		ArrayList<String> files_C2 = FileHandler.getFilenames(Utilities.PCAP_SSH_CAPTURE2_DIR, false, "");
		ArrayList<String> files_C3 = FileHandler.getFilenames(Utilities.PCAP_SSH_CAPTURE3_DIR, false, "");

		ArrayList<Session> sessions = ProcessKippoLogs.getStealthySessions();
		ArrayList<TCPFlow> flows = new ArrayList<TCPFlow>();
		sessions.forEach((session) -> flows.addAll(session.flows));

		ArrayList<String> lines = new ArrayList<String>();
		lines.add("sIP,dIP,dPort,avgPktLen");
		for (TCPFlow flow : flows) {
			long sIP = Utilities.ipToLong(flow.srcIP);
			long dIP = Utilities.ipToLong(flow.dstIP);

			ArrayList<String> matchingFilenames = Utilities.getFilenames(files_C2, files_C3, flow);
			if (matchingFilenames.size() == 1) {
				double avgPktLen = Choi2008.getAveragePktLen(matchingFilenames.get(0));
				lines.add(sIP + "," + dIP + "," + flow.dstPort + "," + avgPktLen);
			}

			matchingFilenames.clear();
		}

		FileHandler.write("/home/gokul/Documents/dataset_choi2008.csv", new ArrayList<Object>(lines), false, "\n");
	}

}
