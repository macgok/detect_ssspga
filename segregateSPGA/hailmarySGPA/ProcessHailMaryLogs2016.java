package segregateSPGA.hailmarySGPA;

import java.util.ArrayList;
import java.util.Collections;

import segregateSPGA.utilities.FileHandler;

public class ProcessHailMaryLogs2016 {
	public static final String DIR_HAILMARY_DATASET_2016 = FileHandler.COMMON_DIRECTORY + "2008-2019_Dataset_HailMary_Botnet/2016-2019_Dataset/";
	
	public static void main(String[] args) {
		ArrayList<String> filenames = FileHandler.getFilenames(DIR_HAILMARY_DATASET_2016, false, "");
		Collections.sort(filenames);
		filenames.forEach((a) -> System.out.println(a));
	}

}
