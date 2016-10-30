import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
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

    public static final Pattern hostRegex = Pattern.compile(
        // (IP address)(whitespaces)(characters)
        "^([\\d.]+)([\\s]+)([\\w]+)"
        );
    public static final Pattern logRegex = Pattern.compile(
        "^([\\d]+), ([\\d.]+), ([\\d.]+)"
        );


    static public void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Usage: java PilotsStreamFormatter [filename]");
            System.exit(1);
        }

        String filename = args[0];
        List<String> hosts = new ArrayList<String>();
        TimeZone.setDefault(TimeZone.getTimeZone(timeZoneID));

		try {
			BufferedReader in = new BufferedReader(new FileReader(filename));
			String line = null;

	    	while ((line = in.readLine()) != null && line.length() != 0) {
                Matcher m1 = hostRegex.matcher(line);
                if (m1.find()) {
                    hosts.add(m1.group(3));     // add host
                }
            }
            System.out.println("#" + String.join(",", hosts));

	    	while ((line = in.readLine()) != null) {
                Matcher m2 = logRegex.matcher(line);
                if (m2.find()) {
                    String data = "";
                    List<String> values = new ArrayList<String>();

                    Calendar cal = Calendar.getInstance();
                    cal.setTimeInMillis(Long.parseLong(m2.group(1)));
                    data += ":" + dateFormat.format(cal.getTime()) + ":";

                    for (int i = 2; i <= m2.groupCount(); i++) {
                        values.add(m2.group(i));
                    }
                    data += String.join(",", values);

                    System.out.println(data);
                }
			}
			in.close(); 
		} catch (IOException ex) {
			System.err.println("Error: Can't open the file " + filename + " for reading.");
		}
        
    }
}
