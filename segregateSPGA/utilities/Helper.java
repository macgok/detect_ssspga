/**
 * 
 */
package segregateSPGA.utilities;

import java.util.ArrayList;

import segregateSPGA.dataType.UserAccount;

/**
 * @author gokul
 *
 */
public class Helper {
	public static final boolean DEBUG = true;
	
	public static final short SUCCESS_ATTEMPTS = 1;
	public static final short ALL_ATTEMPTS_WITHOUT_NONE = -2;

	/***
	 * Get user accounts based on the input condition. <br>
	 * 
	 * @param flow
	 * @param status 1 => success attempts <br>
	 *               0 => failure attempts without none <br>
	 *               -1 => all attempts (with none auth. type) <br>
	 *               -2 => all attempts without none <br>
	 *               -3 => all attempts without none and without time = 0 <br>
	 * @return
	 */
	public static ArrayList<UserAccount> getUserAttempts(ArrayList<UserAccount> accounts, short status) {
		ArrayList<UserAccount> matchedUA = new ArrayList<UserAccount>();

		for (UserAccount ua : accounts) {
			switch (status) {
			case Helper.ALL_ATTEMPTS_WITHOUT_NONE:
				if (ua.type.equals(Constants.AUTH_NONE) == false) {
					matchedUA.add(ua);
				}
				break;
			case Helper.SUCCESS_ATTEMPTS:
				if (ua.isSucceeded == true) {
					matchedUA.add(ua);
				}
				break;
			}
		}

		return matchedUA;
	}

	/***
	 * Get an unique set of login attempts. <br>
	 * For example: <br>
	 * If the list is x1, x2, x1, x3, x4. <br>
	 * This method returns x1, x2, x3, x4. <br>
	 * 
	 * @param accounts
	 * @return
	 */
	public static ArrayList<UserAccount> getUniqueLogins(ArrayList<UserAccount> accounts) {
		ArrayList<UserAccount> uniqAccounts = new ArrayList<UserAccount>();
		for (UserAccount account : accounts) {
			if (uniqAccounts.contains(account) == false)
				uniqAccounts.add(account);
		}
		return uniqAccounts;
	}

	/***
	 * Count the number of times a particular UserAccount is repeated in a list.
	 * 
	 * @param target
	 * @param accounts
	 * @return 0 means error, 1 means not repeating
	 */
	public static int getNoOfOccurences(UserAccount target, ArrayList<UserAccount> accounts) {
		int count = 0;

		for (UserAccount ua : accounts) {
			if (ua.compareTo(target) == 0) {
				count++;
			}
		}

		return count;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		
	}

}
