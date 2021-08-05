package ro.gligor.dnsReport;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.TextParseException;

import java.net.UnknownHostException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


class DNSLookupTest {

    @Test
    public void SPFFetcherTest() throws TextParseException {
        List<String> txtRecords = DNSLookup.getSPFRecord("google.com");

        assertTrue(txtRecords.size() > 0);
    }

    @Test
    public void MXRecordTest() throws TextParseException {
      assertTrue(DNSLookup.getMXRecords("google.com").size() > 0);
    }

    @Test
    public void ARecordtest() throws TextParseException {
       assertTrue(DNSLookup.getARecords("google.com"));
    }

    @Test
    public void AAAARecordtest() throws TextParseException {
        assertTrue(DNSLookup.getAAAARecords("google.com"));
    }

    @Test
    public void getDMARCTest() throws TextParseException {
        assertTrue(DNSLookup.getDMARCRecord("google.com").size() > 0);
    }

    @Test
    public void buildSPFTreeTest() throws UnknownHostException {
        /*
        at this time the google SPF is v=spf1 include:_spf.google.com ~all
        the IPs list should be empty and the lookups should be 1

        at this time the aol SPF is:
        v=spf1 ip4:204.29.186.0/23 include:spf.constantcontact.com include:aspmx.sailthru.com include:mail.z
        endesk.com include:_ipspf.yahoo.com ~all
        the size of the IP list should be 1 and the lookup list size should be 4

        if this fails, check if the SPFs changed
        */
        SPFNode googleNode = new SPFNode("google.com", 1);
        SPFNode aolNode = new SPFNode("aol.com", 1);
        assertEquals(0, googleNode.getIPs().size());
        assertEquals(1, googleNode.getLookups().size());
        assertEquals(1, aolNode.getIPs().size());
        assertEquals(4, aolNode.getLookups().size());
    }
}