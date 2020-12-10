package segregateSPGA.utilities;

import java.util.ArrayList;

/***
 * Mathematical functions for different types of entropies.
 * 
 * @author gokul
 *
 */
public class Entropy {

	/***
	 * Calculate and return the shannon entropy. <br>
	 * 
	 * @param probabilities
	 * @return
	 */
	public static double getEntropy(ArrayList<Double> probabilities) {
		double r = 0;

		for (int i = 0; i < probabilities.size(); i++) {
			double p = probabilities.get(i);
			if (p != 0) {
				double r1 = p * Math.log(p) / Math.log(2);
				r += r1;
			}
		}
		r = -r;

		return r;
	}

	/***
	 * 
	 * @param probabilities
	 * @param totalElements
	 * @return -1 if the totalElements is zero.
	 */
	public static double getNormEntropy(ArrayList<Double> probabilities, int totalElements) {
		if (totalElements <= 0) {
			return -1;
		}

		double r = Entropy.getEntropy(probabilities);

		double d = Math.log(totalElements) / Math.log(2);

		return r / d;
	}
}
