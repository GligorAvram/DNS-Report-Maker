package ro.gligor.dnsreport;

public class ParagraphLine {
    private final int depth;
    private final String line;

    public static int totalLookups;

    public ParagraphLine(int depth, String line) {
        this.depth = depth;
        this.line = line;
    }

    public int getDepth() {
        return depth;
    }

    public String getLine() {
        return line;
    }
}
