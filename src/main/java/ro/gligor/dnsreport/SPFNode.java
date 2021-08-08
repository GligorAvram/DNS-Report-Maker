package ro.gligor.dnsreport;

import java.util.ArrayList;
import java.util.List;

public class SPFNode {

    private int depth;
    private final List<SPFNode> lookups;
    private final List<String> IPs;
    private final String domain;

    public SPFNode(String spf, int depth){
        this.lookups = new ArrayList<>();
        this.IPs = new ArrayList<>();
        this.domain = spf;
        this.depth = depth;
    }

    public int getDepth() {
        return depth;
    }

    public List<SPFNode> getLookups() {
        return lookups;
    }

    public List<String> getIPs() {
        return IPs;
    }

    public void addNonNode(String s) {
         IPs.add(s);
    }
    public void addNode(SPFNode node) {
        lookups.add(node);
    }

    public String getDomain() {
        return domain;
    }

    public void increaseDepth(int depth) {
        this.depth = depth;
    }

    public void buildReport(List<ParagraphLine> tree) {
        tree.add(new ParagraphLine(depth, domain));
        if(!IPs.isEmpty()){
            for (String s: IPs
            ) {
                tree.add(new ParagraphLine(depth +1, s));
            }
        }
        if(!lookups.isEmpty()){
            for (SPFNode s: lookups
                 ) {
                ParagraphLine.totalLookups++;
                s.buildReport(tree);
            }
        }
    }
}
