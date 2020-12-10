package segregateSPGA.relatedWorks;

import java.util.ArrayList;

import org.jnetpcap.Pcap;

import segregateSPGA.dataType.TCPFlow;

public class Utilities {
	static final String PCAP_SSH_CAPTURE2_DIR = "/home/gokul/Downloads/D2/";
	static final String PCAP_SSH_CAPTURE3_DIR = "/home/gokul/Downloads/D3/";

	/***
	 * Get the matching filenames.
	 * 
	 * @param files_C2
	 * @param files_C3
	 * @param flow
	 * @return
	 */
	public static ArrayList<String> getFilenames(ArrayList<String> files_C2, ArrayList<String> files_C3, TCPFlow flow) {
		ArrayList<String> matchingFilenames = new ArrayList<String>();

		String sourcePort = Integer.toString(flow.srcPort);
		for (String filename : files_C2) {
			String sourceIP = flow.srcIP.replace('.', '-');
			if (filename.contains(sourceIP) && filename.contains(sourcePort)) {
				matchingFilenames.add(PCAP_SSH_CAPTURE2_DIR + filename);
			}
		}

		for (String filename : files_C3) {
			if (filename.contains(flow.srcIP) && filename.contains(sourcePort)) {
				matchingFilenames.add(PCAP_SSH_CAPTURE3_DIR + filename);
			}
		}

		return matchingFilenames;
	}

	/***
	 * Take IPv4 address in x.x.x.x format and convert to an integer.
	 *
	 * @param ipAddress
	 * @return integer value of an IP address
	 */
	public static long ipToLong(String ipAddress) {
		String[] ipAddressInArray = ipAddress.split("\\.");

		long result = 0;
		for (int i = 0; i < ipAddressInArray.length; i++) {
			int power = 3 - i;
			int ip = Integer.parseInt(ipAddressInArray[i]);
			result += ip * Math.pow(256, power);
		}

		return result;
	}

	/**
	 * Open a pcap file offline. <br>
	 * Write the errro message in the error log file. <br>
	 * 
	 * @param filename
	 * @return
	 */
	public static Pcap getPcapObject(String filename) {
		StringBuilder builder = new StringBuilder();
		Pcap pcap = Pcap.openOffline(filename, builder);
		if (pcap == null) {
			System.err.println(builder.toString());
			return null;
		}
		return pcap;
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
