package ml;

import java.util.ArrayList;

public class DistanceMatrix {
	/**
	 * Take a list of strings. <br>
	 * Each string is delimited by a character. <br>
	 * Convert this one string into a row in an array. <br>
	 * Return the 2D array.
	 *
	 * @param data
	 * @return two-dimensional string array
	 */
	public static String[][] convertToStringArray(ArrayList<String> data, String delimiter) {
		String[][] array = null;
		String[] tokens = null;
		int i = 0, j = 0;

		array = new String[data.size()][];

		for (i = 0; i < data.size(); i++) {
			tokens = data.get(i).split(delimiter, -1);
			array[i] = new String[tokens.length];
			for (j = 0; j < tokens.length; j++) {
				array[i][j] = tokens[j];
			}
		}

		return array;
	}
	
	/***
	 * Compute the similarity matrix using euclidean distance with weights. <br>
	 * 
	 * @param dataset
	 * @param weights
	 * @param similarity
	 * @return
	 */
	public static double[][] getSimilarityMatrix(double[][] dataset, double[] weights, boolean similarity) {
		// Sum of all weights should be equal to 1.
		double wg_sum = 0;
		for (double w : weights) {
			wg_sum += w;
		}
		if (wg_sum != 1) {
			return null;
		}

		// Column length of dataset should be equal to the length of the weights
		int noOfColumns = dataset[0].length;
		if (noOfColumns != weights.length) {
			return null;
		}

		// Compute similarity matrix
		int noOfRows = dataset.length;
		double[][] sMatrix = new double[noOfRows][noOfRows];
		for (int r1 = 0; r1 < noOfRows; r1++) {
			for (int r2 = 0; r2 < noOfRows; r2++) {
				double s = 0;
				for (int c = 0; c < noOfColumns; c++) {
					double e1 = dataset[r1][c];
					double e2 = dataset[r2][c];

					if (Double.isNaN(e1) == false && Double.isNaN(e2) == false) {
						double a1 = (e1 - e2) * (e1 - e2);
						double a2 = weights[c] * a1;
						s += a2;
					}
				}
				double s1 = Math.sqrt(s);
				if (similarity == true) {
					sMatrix[r1][r2] = 1 - s1;
				} else {
					sMatrix[r1][r2] = s1;
				}

			}
		}

		return sMatrix;
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
