import java.io.*;
import java.util.*;
import java.util.regex.Pattern;

/**
 * This class takes in a file and threshold argument and checks if they have valid inputs and meet the threshold condition.
 *
 * @author Andrew Hwang
 */
public class InputCheck {

    final static String ip = "\\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\\b";
    final static String domainName = "[(][-a-zA-Z0-9@:%_\\+.~#?&//=]{2,256}\\.[a-z]{2,4}\\b(\\/[-a-zA-Z0-9@:%_\\+.~#?&//=]*)?(\\?([-a-zA-Z0-9@:%_\\+.~#?&//=]+)|)[)]";
    final static String thresholdLine = "(: [0-9]* times)";

    final static Pattern ipPattern = Pattern.compile(ip);
    final static Pattern domainPattern = Pattern.compile(domainName);
    final static Pattern thresholdPattern = Pattern.compile(thresholdLine);

    static TreeSet<String> outputStandard;

    static int threshold;

    public static void main(String[] args) {
        outputStandard = new TreeSet<>();

        setThreshold(args);

        String filename = "file.txt";

        String line;

        try {
            assert threshold > 0 : "The there is no threshold value";
            FileReader fileReader = new FileReader(filename);

            BufferedReader reader = new BufferedReader(fileReader);

            while ((line = reader.readLine()) != null) {
                String[] segments = line.split(" ");
                if (checkExtensiveThreshold(line, threshold)) {
                    if (checkConditions(segments)) {

                        String out = outwards(segments);
                        outputStandard.add(out);
                    }
                }
            }


            Iterator<String> iterator = outputStandard.iterator();
            while (iterator.hasNext()) {
                String output = iterator.next();
                System.out.println(output);
            }

            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("Cannot Open File '" + filename + "'");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void setThreshold(String[] args) {
        if (args.length > 0) {
            threshold = Integer.parseInt(args[0]);
        }
        else {
            threshold = 3;
        }
    }

    private static String outwards(String[] segments) {
        StringBuilder builder = new StringBuilder();
        String out = "";

        assert ipValid(segments) : "The IP address is Invalid.";

        for (String s: segments) {
            if (ipPattern.matcher(s).find() && out.length() < 1) {
                out = s.substring(0, s.length() - 1);
            }
            else if (domainPattern.matcher(s).find()) {
                out = s.substring(1, s.length() - 2);
                break;
            }
        }

        builder.append(" ");
        builder.append(out);
        builder.append(",");
        return builder.toString();
    }

    private static boolean ipValid(String[] lineSegments) {
        boolean isValid = false;
        for (String s: lineSegments) {
            if (ipPattern.matcher(s).find()) {
                if (!domainPattern.matcher(s).find()) {
                    isValid = true;
                }
            }
        }
        return isValid;
    }

    private static boolean domainNameValid(String[] lineSegments) {
        assert ipValid(lineSegments) : "The IP address is Invalid.";
        boolean isValid = false;
        for (String s: lineSegments) {
            if (domainPattern.matcher(s).find()) {
                isValid = true;
            }
        }
        return isValid;
    }

    private static boolean checkExtensiveThreshold(String line, int threshold) {
        int numberOfAttempts;
        boolean isValid = false;
        if (thresholdPattern.matcher(line).find()) {
            String[] segments = line.split(" ");
            String times = "times";
            int index = java.util.Arrays.asList(segments).indexOf(times);
            numberOfAttempts = Integer.parseInt(segments[index - 1]);
            if (numberOfAttempts > threshold) {
                System.out.println("The User had " + numberOfAttempts + " failed login attempts");
                isValid = true;
            }
            else {
                System.out.println("The is no threshold value");
            }
        }

        return isValid;
    }

    private static boolean checkConditions(String[] segments) {
        boolean isValid = false;
        if (ipValid(segments)) {
            System.out.println("The IP address is Valid");
            if (domainNameValid(segments)) {
                System.out.println("The Domain name is Valid");
            } else {
                System.out.println("There is no Valid Domain name");
            }
            isValid = true;
        } else {
            System.out.println("There is no Valid IP address");
        }
        return isValid;
    }
}
