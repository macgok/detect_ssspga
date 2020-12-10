/**
 * 
 */
package segregateSPGA.dataType;

import java.util.ArrayList;
import java.util.StringJoiner;

/**
 * @author gokul
 *
 */
public class TCPFlow {
	public String srcIP;
	public String dstIP;
	public int srcPort;
	public int dstPort;
	public long sessionID;

	public ArrayList<UserAccount> accounts = new ArrayList<UserAccount>();
	public int failedAttempts;
	public int successAttempts;

	public long startTime;
	public long endTime;

	public String remoteSSHVersion;

	public String kex_algorithm;
	public String key_algorithm;
	public String outgoing_encr_algorithm;
	public String outgoing_hash_algorithm;
	public String outgoing_comp_algorithm;

	public long noOfPkts;

	public String pcapFilename;

	@Override
	public String toString() {
		return this.getAllInfo();
	}

	public String getInfo_Pouget2004() {
		StringJoiner joiner = new StringJoiner(", ", "", "");

		joiner.add(Long.toString(startTime));
		joiner.add(srcIP);
		joiner.add(Integer.toString(dstPort));
		joiner.add(Long.toString(endTime));
		joiner.add(Long.toString(noOfPkts));

		return joiner.toString();
	}

	public String getAllInfo() {
		StringJoiner joiner = new StringJoiner(", ", "", "");

		joiner.add(getTCPInfo());

		joiner.add(Long.toString(startTime));
		joiner.add(Long.toString(endTime));

		joiner.add(remoteSSHVersion);
		joiner.add(kex_algorithm);
		joiner.add(key_algorithm);

		joiner.add(outgoing_encr_algorithm);
		joiner.add(outgoing_hash_algorithm);
		joiner.add(outgoing_comp_algorithm);

		joiner.add(getUserAccountInfo());

		joiner.add(Long.toString(noOfPkts));
		joiner.add(pcapFilename);

		return joiner.toString();

	}

	public String getTCPInfo() {
		StringJoiner joiner = new StringJoiner(", ", "", "");

		joiner.add(srcIP);
		joiner.add(Integer.toString(srcPort));
		joiner.add(dstIP);
		joiner.add(Integer.toString(dstPort));

		return joiner.toString();
	}

	public String getUserAccountInfo() {
		StringJoiner joiner = new StringJoiner("\n", "<", ">");

		for (UserAccount ua : accounts) {
			joiner.add(ua.toString());
		}

		return joiner.toString();
	}

}
