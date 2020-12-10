/**
 * 
 */
package segregateSPGA.utilities;

/**
 * @author gokul
 *
 */
public class Constants {
	/***
	 * If there are no packets for a duration of this interval, <br>
	 * then all packets before and after are put in two different sessions. <br>
	 */
	public static long SESSION_GAP_INTERVAL = 100;

	// Single-source BFA
	public final static long DURATION = 10 * 60; // 10 minutes (600 seconds) - Default in fail2ban
	public final static long BAN_TIME = 10 * 60; // 10 minutes (600 seconds) - Default in fail2ban
	public final static int MAX_RETRIES = 3; // number of retries - Default in fail2ban

	// Used by Helper.java
	public final static String AUTH_NONE = "none";
	
	
}
