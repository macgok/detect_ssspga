/**
 * 
 */
package segregateSPGA.utilities;

import java.lang.reflect.Field;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author gokul
 *
 */
public class Utilities {
	/***
	 * Get a line and find matching pattern. <br>
	 *
	 * @param line a line in the kippo log file
	 * @return if no matching pattern, then return null.
	 */
	public static String getMatchPattern(String line, String patternString) {
		Pattern pattern = Pattern.compile(patternString);
		Matcher m = pattern.matcher(line);
		String result = null;

		try {
			if (m.find()) {
				result = m.group();
			}
		} catch (IllegalStateException ex) {
			ex.printStackTrace();
		}

		return result;
	}

	/***
	 * 
	 * @param line a line in kippo log file
	 * @return
	 */
	public static String getMatchPattern(String line, String regexString, String rmString) {
		String tempString = getMatchPattern(line, regexString);
		if (tempString != null) {
			String result = tempString.replace(rmString, "");
			return result;
		} else
			return null;
	}

	/***
	 * Check if the string is empty and null. <br>
	 * 
	 * @param string
	 * @return
	 */
	public static boolean isEmptyOrNull(String string) {
		if (string == null || string.isEmpty()) {
			return true;
		} else {
			return false;
		}
	}

	/***
	 * Check if a particular field value is the same in all the Objects in a list.
	 * <br>
	 *
	 * @param objList
	 * @param fieldName
	 * @return
	 */
	@SuppressWarnings("rawtypes")
	public static boolean allSameField(ArrayList<Object> objList, String fieldName) {
		String fieldValue = null;

		for (Object object : objList) {
			try {
				Class c = object.getClass();
				Field f = c.getDeclaredField(fieldName);
				String fVal = (String) f.get(object);

				if (fieldValue == null) {
					fieldValue = fVal;
				} else {
					if (isEmptyOrNull(fVal) == false && fVal.equals(fieldValue) == false) {
						return false;
					}
				}
			} catch (Exception ex) {
	
			}
		}

		return true;
	}
	
	public static boolean allSameField(ArrayList<Object> objList, String[] fieldNames) {
		boolean status = true;

		for (String fieldName : fieldNames) {
			status = allSameField(objList, fieldName) && status;
			if (status == false)
				break;
		}

		return status;
	}

	/***
	 * Count the number of digits in an integer. <br>
	 * 
	 * @param num
	 * @return
	 */
	public static int getCountOfDigits(long num) {
		int count = 0;

		while (num != 0) {
			num /= 10;
			count++;
		}

		return count;
	}

	/***
	 * Get a human-readable date from time stamp. <br>
	 * 
	 * @param ts     less than or equal to 13 digits
	 * @param format
	 * @return
	 */
	public static String getDate(long ts, String format) {
		int cntDigits = getCountOfDigits(ts);
		int diff = 13 - cntDigits;
		if (diff > 0) {
			ts = (long) (ts * (Math.pow(10, diff)));
		}
		Date d = new Date(ts);
		SimpleDateFormat sd = new SimpleDateFormat(format);
		return sd.format(d);
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
