package ro.gligor.dnsReport;

public class ParagraphLine {
    private final int depth;
    private final String line;

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
