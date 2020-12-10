/**
 * 
 */
package segregateSPGA.dataType;

import java.util.StringJoiner;

import segregateSPGA.utilities.Utilities;

/**
 * @author gokul
 *
 */
public class UserAccount implements Comparable<UserAccount> {
	public String username;
	public String password;
	public String type;
	public long dateTime;
	public boolean isSucceeded;

	public UserAccount() {
		this.username = "";
		this.password = "";
	}

	public UserAccount(String type) {
		this();
		this.type = type;
	}
	
	@Override
	public String toString() {
		StringJoiner joiner = new StringJoiner("/", "[", "]");

		joiner.add(this.type);
		joiner.add(this.username);
		joiner.add(this.password);
		joiner.add(Utilities.getDate(this.dateTime, "yyyy-MM-dd HH:mm:ss"));

		String status = isSucceeded ? "Success" : "Failure";
		joiner.add(status);

		return joiner.toString();
	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof UserAccount) {
			UserAccount ua = (UserAccount) o;
			if (this.username.equals(ua.username) && this.password.equals(ua.password) && this.type.equals(ua.type))
				return true;
		}
		return false;
	}

	@Override
	public int compareTo(UserAccount ua) {
		int v1 = this.type.compareTo(ua.type);
		int v2 = this.username.compareTo(ua.username);
		int v3 = this.password.compareTo(ua.password);

		if (v1 == 0 && v2 == 0 && v3 == 0)
			return 0;

		if (v1 != 0)
			return v1;
		else if (v2 != 0)
			return v2;
		else
			return v3;
	}

}
