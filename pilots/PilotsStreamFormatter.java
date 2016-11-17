import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.TimeZone;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.text.ParseException;

public class PilotsStreamFormatter {
    public static DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HHmmssSSSZ");
    public static String timeZoneID = "America/New_York";
    public static int SRC = 0;
    public static int DST = 1;

    public static final Pattern hostRegex = Pattern.compile(
        // (IP address)(whitespaces)(characters)
        "^([\\d.]+)([\\s]+)([\\w]+)"
        );
    public static final Pattern logRegex = Pattern.compile(
        // Did not work. Used split instead...
        "^([\\d]+), ([\\d.]+), ([\\d.]+)"
        );

    
    public static boolean hostsMatched(String[][] filters, String src, String dst) {
        boolean matched = false;
        for (int i = 0; matched == false && i < filters.length; i++) {
            matched = src.contains(filters[i][SRC]) && dst.contains(filters[i][DST]);
            // System.out.println("filters[" + i + "][" + SRC + "]=" + filters[i][SRC] + ", " + 
            //                    "filters[" + i + "][" + DST + "]=" + filters[i][DST] + ", " + 
            //                    "src=" + src + ", " +
            //                    "dst=" + dst + ", " + 
            //                    "matched=" + matched);
        }
        return matched;
    }

    public static void main(String[] args) {
        if (args.length < 1 || 2 < args.length) {
            System.err.println("Usage: java PilotsStreamFormatter [filename] [filters]");
            System.exit(1);
        }

        String filename = args[0];
        String myhost = filename.substring(filename.lastIndexOf('/') + 1, 
                                           filename.lastIndexOf('.'));
        String[][] filters = null;
        Boolean useFilter = false;
        if (2 <= args.length) {
            // filter format: src1:dst1,src1:dst1,...
            String[] filterStrs = args[1].split(",");
            filters = new String[filterStrs.length][2];
            for (int i = 0; i < filterStrs.length; i++) {
                filters[i] = filterStrs[i].split(":");
            }
            useFilter = true;
        }

		try {
            List<String> hosts = new ArrayList<String>();
            List<Integer> matchedIndexList = new ArrayList<Integer>();
            TimeZone.setDefault(TimeZone.getTimeZone(timeZoneID));

			BufferedReader in = new BufferedReader(new FileReader(filename));
			String line = null;

            // First, parse the list of hosts
            int index = 0;
	    	while ((line = in.readLine()) != null && line.length() != 0) {
                // Assuming there is a blank line before the traffic data
                Matcher m1 = hostRegex.matcher(line);
                Boolean matched = true;
                if (m1.find()) {
                    String host = m1.group(3);
                    if (useFilter)
                        matched = hostsMatched(filters, myhost, host);
                    if (matched) {
                        matchedIndexList.add(index);
                        hosts.add(host);
                    }
                    index++;
                }

            }

            if (hosts.size() == 0) {
                System.exit(1);
            }
            System.out.println("#" + String.join(",", hosts));
            
            // Next, parse the traffic measurements
	    	while ((line = in.readLine()) != null) {
                String data = "";
                String items[] = line.split(", ");
                if (items[0].contains(".")) // if IP address is found, quit
                    break;

                // items[0]: time in msec
                Calendar cal = Calendar.getInstance();
                cal.setTimeInMillis(Long.parseLong(items[0]));
                data += ":" + dateFormat.format(cal.getTime()) + ":";

                // items[1-n]: comm data
                String[] values = null;
                if (useFilter) {
                    values = new String[matchedIndexList.size()];
                    int valIndex = 0;
                    for (Integer matchedIndex : matchedIndexList) {
                        values[valIndex++] = items[matchedIndex + 1];
                        // System.out.println("matchedIndex=" + matchedIndex);
                    }
                }
                else {
                    values = Arrays.copyOfRange(items, 1, items.length);
                }
                data += String.join(",", values);

                System.out.println(data);
			}

			in.close(); 
		} catch (IOException ex) {
			System.err.println("Error: Can't open the file " + filename + " for reading.");
		}
        
    }
}
