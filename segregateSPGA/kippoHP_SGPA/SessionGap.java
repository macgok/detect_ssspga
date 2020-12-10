package segregateSPGA.kippoHP_SGPA;

import java.util.ArrayList;

import segregateSPGA.SessionCreator;
import segregateSPGA.dataType.TCPFlow;

public class SessionGap {

	public static void main(String[] args) {
		ArrayList<TCPFlow> flows = ProcessKippoLogs.getAllMergedFlows();
		String filename = "/home/gokul/Documents/sessionGaps.csv";
		long[] p1 = new long[] { 0, 2000, 1 };
		
		SessionCreator.writeSessionCount(p1, flows, filename);
	}

}
