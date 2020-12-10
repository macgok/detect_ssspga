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
public class Session {
	public ArrayList<TCPFlow> flows = new ArrayList<TCPFlow>();

	public Session(TCPFlow newFlow) {
		this.flows.add(newFlow);
	}

	public Session(ArrayList<TCPFlow> flows) {
		this.flows = flows;
	}

	@Override
	public String toString() {
		StringJoiner buffer = new StringJoiner("\n", "[", "]");

		for (TCPFlow flow : this.flows) {
			buffer.add(flow.toString());
		}

		return buffer.toString();
	}
}
