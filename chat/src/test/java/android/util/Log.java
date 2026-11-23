package android.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Test double of android.util.Log for the JVM unit tests: it records every line the code under test logs, so that a test can scan what logcat would
 * have received. It shadows the stub of the Android jar (test classes come first on the classpath); it prints nothing and returns 0, as the stub does.
 */
public final class Log {
    public static final int VERBOSE = 2, DEBUG = 3, INFO = 4, WARN = 5, ERROR = 6, ASSERT = 7;
    private static final List<String> LINES = Collections.synchronizedList(new ArrayList<String>());

    private Log() {}

    /** Every line logged since the last [clear], as "level/tag: message (throwable text)". */
    public static List<String> captured() {
        synchronized (LINES) { return new ArrayList<String>(LINES); }
    }

    public static void clear() { LINES.clear(); }

    private static int rec(String level, String tag, String msg, Throwable tr) {
        LINES.add(level + "/" + tag + ": " + msg + (tr != null ? " (" + tr + ")" : ""));
        return 0;
    }

    public static int v(String tag, String msg) { return rec("V", tag, msg, null); }
    public static int v(String tag, String msg, Throwable tr) { return rec("V", tag, msg, tr); }
    public static int d(String tag, String msg) { return rec("D", tag, msg, null); }
    public static int d(String tag, String msg, Throwable tr) { return rec("D", tag, msg, tr); }
    public static int i(String tag, String msg) { return rec("I", tag, msg, null); }
    public static int i(String tag, String msg, Throwable tr) { return rec("I", tag, msg, tr); }
    public static int w(String tag, String msg) { return rec("W", tag, msg, null); }
    public static int w(String tag, String msg, Throwable tr) { return rec("W", tag, msg, tr); }
    public static int w(String tag, Throwable tr) { return rec("W", tag, "", tr); }
    public static int e(String tag, String msg) { return rec("E", tag, msg, null); }
    public static int e(String tag, String msg, Throwable tr) { return rec("E", tag, msg, tr); }
    public static int wtf(String tag, String msg) { return rec("A", tag, msg, null); }
    public static int println(int priority, String tag, String msg) { return rec("P" + priority, tag, msg, null); }
    public static boolean isLoggable(String tag, int level) { return true; }
    public static String getStackTraceString(Throwable tr) { return tr == null ? "" : tr.toString(); }
}
