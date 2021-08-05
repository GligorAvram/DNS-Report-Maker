package ro.gligor.dnsReport;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import org.xbill.DNS.*;

import javax.swing.*;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.net.UnknownHostException;
import java.util.List;


public class PdfWriterClass {

    //todo print in the document when something went wrong parsing the records
    //todo records don't have spaces in between the words. FIX IT. <- first priority after making the spf tree
    public void createDocument(String domain) throws FileNotFoundException, DocumentException {

        JFileChooser fc = new JFileChooser();
        int returnValue = fc.showSaveDialog(null);
        String path = "";

        if(returnValue == JFileChooser.APPROVE_OPTION) {
            path=fc.getSelectedFile().getPath();
        }

        Document report = new Document();
        PdfWriter.getInstance(report, new FileOutputStream(path + ".pdf"));

        report.open();
        Font normalFont = FontFactory.getFont(FontFactory.COURIER, 16, BaseColor.BLACK);
        Font errorFont = FontFactory.getFont(FontFactory.COURIER, 16, BaseColor.RED);

        //domain name
        Paragraph domainName = new Paragraph("DNS Records for " + domain, normalFont);
        domainName.setAlignment(Element.ALIGN_CENTER);
        report.add(domainName);

        //mx records
        Paragraph mxRecordTitle = new Paragraph("\nDomain MX records:\n\n");
        
        mxRecordTitle.setIndentationLeft(25);
        report.add(mxRecordTitle);

        try {
            List<MXRecord> mxLookup = DNSLookup.getMXRecords(domain);
            PdfPTable mxTable = createMxTable(mxLookup);

            if(mxTable != null) {
                report.add(mxTable);
            }
            else{
                report.add(new Paragraph("The domain might not have MX records", errorFont));
            }
        } catch (TextParseException e) {
           Paragraph p = new Paragraph("An error occurred when parsing the MX records", errorFont);
           report.add(p);
           e.printStackTrace();
        }

        //DMARC record
        Paragraph DMARCRecordTitle = new Paragraph("\n\nDomain DMARC record:\n\n");
        DMARCRecordTitle.setIndentationLeft(25);
        report.add(DMARCRecordTitle);
        try {
            List<Record> DMARCLookup = DNSLookup.getDMARCRecord(domain);
            PdfPTable dmarcTable = createDMARCTable(DMARCLookup);

            if(dmarcTable != null){
                report.add(dmarcTable);
            }
            else{
                Paragraph p = new Paragraph("The domain might not have a DMARC record", errorFont);
                report.add(p);
            }
        } catch (TextParseException e) {
            Paragraph p = new Paragraph("An error occurred when trying to retrieve the DMARC record", errorFont);
            report.add(p);
            e.printStackTrace();
        }
        report.add(new Paragraph("\n\n"));

        //spf records
        Paragraph SPFRecordTitle = new Paragraph("\n\nDomain SPF record:\n\n");
        SPFRecordTitle.setIndentationLeft(25);
        report.add(SPFRecordTitle);
        List<String> spfRecord;
        try {
            spfRecord = DNSLookup.getSPFRecord(domain);
            if(spfRecord.isEmpty()){
                report.add(new Paragraph("The domain might not have an SPF record.", errorFont));
            }
            if(spfRecord.size() > 1){
                //todo case study: check if this changes everything after as well
                report.add(new Paragraph("Domain has more than one SPF record", errorFont));
            }
            for (String spf: spfRecord
            ) {
                report.add(new Paragraph(String.valueOf(spf)));
            }
            report.add(new Paragraph("\n"));
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        //spf breakup section
        Paragraph SPFBreakupSection = new Paragraph("\n\nDomain SPF breakup:\n\n");
        report.add(SPFBreakupSection);

        try {
            SPFNode rootNode = DNSLookup.spfHierarchy(domain, 1);
            List<ParagraphLine> traversedTree= DNSLookup.traverse(rootNode);
            if(traversedTree.size() > 1) {

                for (ParagraphLine p : traversedTree
                ) {
                    Paragraph spfLine = new Paragraph(p.getLine());
                    spfLine.setIndentationLeft(p.getDepth() * 25);
                    report.add(spfLine);
                }
            }
            else{
                Paragraph noSpf = new Paragraph("There is no SPF to parse");
                report.add(noSpf);
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }


        //DKIM records
        Paragraph DKIMKeysTitle = new Paragraph("\n\nDKIM Keys found:\n\n");
        DKIMKeysTitle.setIndentationLeft(25);
        report.add(DKIMKeysTitle);
        try {
            List<String> dkimKeys = DNSLookup.getDKIMKeys(domain);
            PdfPTable dkimTable = createDKIMTable(dkimKeys);

            if(dkimTable != null){
                report.add(dkimTable);
            }
            else{
                Paragraph p = new Paragraph("Did not find any DKIM keys");
                report.add(p);
            }
        } catch (TextParseException e) {
            Paragraph p = new Paragraph("An error occurred when trying to retrieve the domains DKIM keys", errorFont);
            report.add(p);
            e.printStackTrace();
        }

        report.close();
    }

    private PdfPTable createDKIMTable(List<String> dkimKeys) {
        PdfPTable dkimTable = new PdfPTable(1);
        dkimTable.setWidthPercentage(90);
        dkimTable.addCell("List of DKIM keys");

        if(dkimKeys != null && !dkimKeys.isEmpty()) {
            for (String s : dkimKeys
            ) {
                dkimTable.addCell(s);
            }
        }
        else{
            return null;
        }

        return dkimTable;
    }

    //create the table with the DMARC records that will be printed in the report
    private PdfPTable createDMARCTable(List<Record> dmarcLookup) {
        if(dmarcLookup!=null && !dmarcLookup.isEmpty()){
            PdfPTable dmarcTable = new PdfPTable(new float[]{1, 1, 1, 3});
            dmarcTable.setWidthPercentage(90);
            dmarcTable.addCell("Domain");
            dmarcTable.addCell(" ");
            dmarcTable.addCell("Type");
            dmarcTable.addCell("Record");

            for (Record r: dmarcLookup
                 ) {
                dmarcTable.addCell(r.getName().toString());
                dmarcTable.addCell("IN");
                dmarcTable.addCell(recordToText(r.getType()));
                dmarcTable.addCell(r.rdataToString());
            }
            return dmarcTable;
        }
        return null;
    }

    //create the table with the MX records that will be printed in the report
    private PdfPTable createMxTable(List<MXRecord> mxLookup) {
        if(mxLookup != null && !mxLookup.isEmpty()) {

            PdfPTable mxTable = new PdfPTable(new float[]{1, 1, 1, 3});
            mxTable.setWidthPercentage(90);

            mxTable.addCell("Domain");
            mxTable.addCell(" ");
            mxTable.addCell("Type");
            PdfPCell recordCell = new PdfPCell();

            recordCell.addElement(new Chunk("Record"));
            mxTable.addCell(recordCell);

            for (MXRecord mx : mxLookup
            ) {
                mxTable.addCell(mx.getName().toString());
                mxTable.addCell("IN");
                mxTable.addCell(recordToText(mx.getType()));
                mxTable.addCell(mx.getAdditionalName().toString());
            }

            return mxTable;
        }
        return null;
    }

    private String recordToText(int type) {
        switch(type) {
            case Type.TXT:
                return "TXT";
            case Type.CNAME:
                return "CNAME";
            case Type.MX:
                return "MX";
            case Type.NS:
                return "NS";
            case Type.A:
                return "A";
            case Type.AAAA:
                return "AAAA";}

        return "Record type not found";
    }


}
