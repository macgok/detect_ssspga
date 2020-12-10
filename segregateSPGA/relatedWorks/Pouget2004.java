package segregateSPGA.relatedWorks;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapStat;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import segregateSPGA.dataType.Session;
import segregateSPGA.dataType.TCPFlow;
import segregateSPGA.kippoHP_SGPA.ProcessKippoLogs;
import segregateSPGA.utilities.FileHandler;
import segregateSPGA.utilities.Helper;

public class Pouget2004 {
	private static final String PCAP_CAPTURE2_DIR = "/home/gokul/Downloads/D2_ALL/";

	/***
	 * Compare based on the start time. <br>
	 * Sort it in ascending order. <br>
	 */
	public static Comparator<TCPFlow> comparatorTCPFlow = new Comparator<TCPFlow>() {
		@Override
		public int compare(TCPFlow flow1, TCPFlow flow2) {
			if (flow1.startTime < flow2.startTime)
				return 1;
			else if (flow1.startTime > flow2.startTime)
				return -1;
			else
				return 0;
		}
	};

	/***
	 * Get TCP Flow details.
	 *
	 * @param dirName - contains several pcap files. Each file is a TCP flow.
	 * @return an arraylist of flow details
	 */
	public static ArrayList<TCPFlow> getTCPflows(String dirName) {
		ArrayList<String> files = FileHandler.getFilenames(dirName, false, "");
		ArrayList<TCPFlow> flows = new ArrayList<TCPFlow>();

		for (String filename : files) {
			System.out.println(filename);

			String absFilename = dirName + "/" + filename;
			Pcap pcap = Utilities.getPcapObject(absFilename);
			if (pcap == null) {
				continue;
			}

			PcapPacket packet = new PcapPacket(JMemory.POINTER);
			TCPFlow flow = new TCPFlow();

			// Take the first packet (SYN, ACK, etc.)
			if (pcap.nextEx(packet) == Pcap.NEXT_EX_OK) {
				Ip4 ip = new Ip4();
				if (packet.hasHeader(ip)) {
					flow.srcIP = Integer.toString(ip.sourceToInt());
				}

				Tcp tcp = new Tcp();
				if (packet.hasHeader(tcp)) {
					flow.dstPort = tcp.destination();
				}

				flow.startTime = packet.getCaptureHeader().timestampInMillis();
			}

			int count = 0;
			while (pcap.nextEx(packet) == Pcap.NEXT_EX_OK) {
				count++;
				flow.endTime = packet.getCaptureHeader().timestampInMillis();
			}

			pcap.close();

			flow.noOfPkts = count;
			flows.add(flow);
		}

		Collections.sort(flows, Pouget2004.comparatorTCPFlow);

		return flows;
	}

	/***
	 * Find the count of all the packets in the pcap file. <br>
	 * 
	 * @param filename
	 * @return -1 on error.
	 */
	public static int getCount(String filename) {
		Pcap pcap = Pcap.openOffline(filename, new StringBuilder());
		if (pcap == null) {
			return -1;
		}

		PcapPacket packet = new PcapPacket(JMemory.POINTER);
		int count = 0;
		while (pcap.nextEx(packet) == Pcap.NEXT_EX_OK) {
			count++;
		}

		pcap.close();

		return count;
	}

	public static void main(String[] args) {
		ArrayList<Session> sessions = ProcessKippoLogs.getStealthySessions();
		ArrayList<String> files_C2 = FileHandler.getFilenames(Utilities.PCAP_SSH_CAPTURE2_DIR, false, "");
		ArrayList<String> files_C3 = FileHandler.getFilenames(Utilities.PCAP_SSH_CAPTURE3_DIR, false, "");

		for (Session session : sessions) {
			for (TCPFlow flow : session.flows) {
				ArrayList<String> matchingFilenames = Utilities.getFilenames(files_C2, files_C3, flow);
				if (matchingFilenames.size() == 1) {
					flow.pcapFilename = matchingFilenames.get(0);
					flow.noOfPkts = Pouget2004.getCount(matchingFilenames.get(0));
				}
			}
		}

		if (Helper.DEBUG) {
			FileHandler.write("/home/gokul/Documents/stealthy_sessions_Pouget2004", new ArrayList<Object>(sessions),
					false, "\n");
		}

		ArrayList<SessionUpdated> sessionUpdatedList = new ArrayList<SessionUpdated>();
		for (Session session : sessions) {
			int noOfPkts = 0;
			for (TCPFlow flow : session.flows) {
				noOfPkts += flow.noOfPkts;
			}

			SessionUpdated sessionU = new SessionUpdated();
			sessionU.session = session;
			sessionU.noOfPkts = noOfPkts;
			
			sessionUpdatedList.add(sessionU);
		}
		
		
	}

}
