package ro.gligor.dnsReport;

import org.xbill.DNS.Record;
import org.xbill.DNS.*;

import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

public class DNSLookup {



    public static List<String> getSPFRecord(String domain) throws TextParseException {
        List<String> SPFRecordList = new ArrayList<>();

        Record[] txtRecords;

            txtRecords = new Lookup(domain, Type.TXT).run();

            if (txtRecords != null && txtRecords.length > 0) {
                for (Record r: txtRecords
                     ) {
                    if (r.toString().toLowerCase(Locale.ROOT).contains("spf1")) {
                        String s = r.rdataToString();
                        //remove the " of the spf
                        if (s.charAt(0) == '"' && s.charAt(s.length() - 1) == '"'){
                             s = s.substring(1, s.length() - 1);
                        }
                        SPFRecordList.add(s);
                    }
                }
            }

        return SPFRecordList;
    }

    public static List<MXRecord> getMXRecords(String domain) throws TextParseException {
        List<MXRecord> MXRecords = new ArrayList<>();

        Record[] records;

            records = new Lookup(domain, Type.MX).run();

        if(records == null){
            return null;
        }
            for (Record r : records
            ) {
                MXRecords.add((MXRecord) r);
            }

        return MXRecords;
    }

    public static boolean getARecords(String domain) throws TextParseException {

        List<String> aRecords = new ArrayList<>();

        Record[] records;

            Lookup lookup = new Lookup(domain, Type.A);
            records = lookup.run();

        return lookup.getResult() == Lookup.SUCCESSFUL && records.length > 0;
    }

    public static boolean getAAAARecords(String domain) throws TextParseException {
        List<String> aRecords = new ArrayList<>();

        Record[] records;

            Lookup lookup = new Lookup(domain, Type.AAAA);
            records = lookup.run();

        return lookup.getResult() == Lookup.SUCCESSFUL && records.length > 0;
    }

    public static List<Record> getDMARCRecord(String domain) throws TextParseException {
        List<Record> dmarc = new ArrayList<>();
        Record[] records;

        records = new Lookup("_dmarc." + domain, Type.CNAME).run();

        if (records != null && records.length > 0) {
            dmarc.addAll(Arrays.asList(records));

            for (Record r : records
                 ) {
                Record[] cnameDig = new Lookup(r.rdataToString(), Type.TXT).run();
                dmarc.addAll(Arrays.asList(cnameDig));
            }
            return dmarc;
        }
        else{
            records = new Lookup("_dmarc." + domain, Type.NS).run();

            if(records != null && records.length >0){
                dmarc.addAll(Arrays.asList(records));
            }
            records= new Lookup("_dmarc." + domain, Type.TXT).run();
            if(records != null && records.length >0){
                dmarc.addAll(Arrays.asList(records));
            }
            else{
                if(dmarc.isEmpty()) {
                    return null;
                }
            }
        }
        return dmarc;
    }


    public static SPFNode spfHierarchy(String domain, int depth) throws UnknownHostException {

        SPFNode node = new SPFNode(domain, depth);

        String domainSPFRecord = "";

        //the if and else if check if this is an include that is received through recursion
        if(domain.startsWith("include:") || domain.startsWith("?include:")){
            String[] s =domain.split(":");
            try {
                domainSPFRecord = String.valueOf(getSPFRecord(s[1]));
                //removes the last ] in case an include is situated at the end
                //the first [ shouldn't need to be removed since it's linked to v=spf1, which is ignored
                if(domainSPFRecord.charAt(domainSPFRecord.length() -1) == ']'){
                    domainSPFRecord = domainSPFRecord.substring(0, domainSPFRecord.length() -1);
                }
            } catch (TextParseException e) {
                e.printStackTrace();
            }
        }
        else if(domain.startsWith("redirect=")){
            String[] s =domain.split("=");
            try {
                domainSPFRecord = String.valueOf(getSPFRecord(s[1]));
            } catch (TextParseException e) {
                e.printStackTrace();
            }
        }
        //the else below gets the include of the domain, breaks it apart and checks if it should start building nodes or not
        else{
            try {
                domainSPFRecord= String.valueOf(getSPFRecord(domain));
                if(domainSPFRecord.charAt(0)=='[' && domainSPFRecord.charAt(domainSPFRecord.length()-1)==']'){
                    domainSPFRecord = domainSPFRecord.substring(1, domainSPFRecord.length()-1);
                }
               } catch (TextParseException e) {
                e.printStackTrace();
            }
        }
        String[] splitRecord = domainSPFRecord.split(" ");

        for (String s: splitRecord
             ) {
            if(s.toLowerCase(Locale.ROOT).startsWith("ip4:") || s.toLowerCase(Locale.ROOT).startsWith("ip6:")){
                node.addNonNode(s);
            }
            else if(s.toLowerCase(Locale.ROOT).startsWith("a:") || s.toLowerCase(Locale.ROOT).startsWith("a/") ||
                    s.toLowerCase(Locale.ROOT).equals("a")){
                node.addNonNode(s);
            }
            else if(s.toLowerCase(Locale.ROOT).startsWith("mx:") || s.toLowerCase(Locale.ROOT).startsWith("mx/") ||
                    s.toLowerCase(Locale.ROOT).equals("mx")){
                node.addNonNode(s);
            }
            else if(s.toLowerCase(Locale.ROOT).startsWith("ptr:") || s.toLowerCase(Locale.ROOT).equals("ptr")){
                SPFNode newNode = spfHierarchy(s, depth +1);
                node.addNode(newNode);
            }
            else if(s.toLowerCase(Locale.ROOT).startsWith("exists:") || s.toLowerCase(Locale.ROOT).startsWith("include:") ||
                    s.toLowerCase(Locale.ROOT).startsWith("?include:") || s.toLowerCase(Locale.ROOT).startsWith("redirect=")){
                SPFNode newNode = spfHierarchy(s, depth +1);
                node.addNode(newNode);
            }
        }
        return node;
    }

    public static List<ParagraphLine> traverse(SPFNode rootNode) {
        List<ParagraphLine> tree = new LinkedList<>();
        rootNode.buildReport(tree);
        return tree;
    }

    public static List<String> getDKIMKeys(String domain) throws TextParseException {
        //list of common DKIM selector
        final List<String> commonSelectors = Arrays.asList("selector1", "selector2", "google", "gsuite", "smtp", "mandrill", "cm", "ep1",
                "zendesk1", "zendesk2", "krs", "m1", "k1", "0", "mx", "pic", "mg", "200608", "10dkim1", "smtpapi","s1", "s2", "cs", "mailo", "bmdeda", "strong1",
                "strong2", "feedblitz", "dk", "hs1", "hs2", "intercom", "mail", "dkim", "pardot", "netsuite", "gs", "gs2", "rmagnet", "turbo-smtp", "etouches",
                "fdm", "fd", "fd2", "fddkim", "s1024", "biz", "biz2", "kesq", "kesp", "veeva", "dynect", "lessonly", "fidelizador", "sign", "crisp", "masterbase",
                "newsletter2go", "key1", "virtrugw", "auth", "ink", "ink2", "rs-dkim", "dkim1024", "lithium", "community", "pm", "mailjet", "qualtrics",
                "neolane", "ecm1", "ecm2", "rmail", "veinteractive", "csod", "v6dk1", "vx", "bb1", "bb2", "flexmail", "splio", "gt", "gt2", "sc", "spop1024",
                "_conversica", "conversica", "poppulo", "gears", "default");
        List<String> DKIMKeys = new ArrayList<>();


        //check if there are CNAME instances of the DKIM selectors and remove the selectors fom the list
        for (String s : commonSelectors) {
            Record[] records;
            String key = s + "._domainkey." + domain;
            records = new Lookup(key, Type.CNAME).run();
            if(records != null && records.length > 0){
                DKIMKeys.add(key);
            }
            else{
                records = new Lookup(key, Type.TXT).run();
                if(records != null && records.length > 0){
                    DKIMKeys.add(key);
                }
            }
        }

        if(DKIMKeys.isEmpty()){
            return null;
        }
        return DKIMKeys;
    }
}
