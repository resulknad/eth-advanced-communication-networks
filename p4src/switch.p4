/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

void mpls_push(in label_t label, in bit s, inout headers hdr) {
    hdr.mpls.push_front(1);
    hdr.mpls[0].setValid();
    hdr.mpls[0].label = label;
    hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
    hdr.mpls[0].s = s;
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {
        // set the src mac address as the previous dst
        // TODO: this is not what happens in reality
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;

        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        // note that we need to extract the ports into metadata fields (conditional on the transport protocol)
        // in the apply { } block because v1model disallows conditionals in actions
        hash(meta.ecmp_hash,
            HashAlgorithm.crc16,
            (bit<1>)0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                meta.srcPort,
                meta.dstPort,
                hdr.ipv4.protocol
            },
            num_nhops
        );

        meta.ecmp_group_id = ecmp_group_id;
    }

    /*
     * This table is the first one to be applied.
     * - For directly connected hosts, it should contain the set_nhop action to forward based on IPv4.
     * - For ingress switches, it should contain the ecmp_group action, which sets the ecmp_group_id (an 
     *   identifier of the set of paths to a particular destination) and the ecmp_hash (an index into this
     *   set based on the flow 5-tuple).
     */
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_nhop;
            ecmp_group;
            drop;
        }
        default_action = drop;
        size = 256;
    }

    action mpls_ingress_1_hop(label_t l1) {
        hdr.ethernet.etherType = TYPE_MPLS;
        mpls_push(l1, 1, hdr);
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_2_hop(label_t l1, label_t l2) {
        mpls_ingress_1_hop(l1);
        mpls_push(l2, 0, hdr);
    }

    action mpls_ingress_3_hop(label_t l1, label_t l2, label_t l3) {
        mpls_ingress_2_hop(l1, l2);
        mpls_push(l3, 0, hdr);
    }

    action mpls_ingress_4_hop(label_t l1, label_t l2, label_t l3, label_t l4) {
        mpls_ingress_3_hop(l1, l2, l3);
        mpls_push(l4, 0, hdr);
    }

    action mpls_ingress_5_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5) {
        mpls_ingress_4_hop(l1, l2, l3, l4);
        mpls_push(l5, 0, hdr);
    }

    action mpls_ingress_6_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6) {
        mpls_ingress_5_hop(l1, l2, l3, l4, l5);
        mpls_push(l6, 0, hdr);
    }

    action mpls_ingress_7_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7) {
        mpls_ingress_6_hop(l1, l2, l3, l4, l5, l6);
        mpls_push(l7, 0, hdr);
    }

    action mpls_ingress_8_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8) {
        mpls_ingress_7_hop(l1, l2, l3, l4, l5, l6, l7);
        mpls_push(l8, 0, hdr);
    }

    action mpls_ingress_9_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9) {
        mpls_ingress_8_hop(l1, l2, l3, l4, l5, l6, l7, l8);
        mpls_push(l9, 0, hdr);
    }

    action mpls_ingress_10_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10) {
        mpls_ingress_9_hop(l1, l2, l3, l4, l5, l6, l7, l8, l9);
        mpls_push(l10, 0, hdr);
    }

    action mpls_ingress_11_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11) {
        mpls_ingress_10_hop(l1, l2, l3, l4, l5, l6, l7, l8, l9, l10);
        mpls_push(l11, 0, hdr);
    }

    action mpls_ingress_12_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11, label_t l12) {
        mpls_ingress_11_hop(l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11);
        mpls_push(l12, 0, hdr);
    }

    action mpls_ingress_13_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11, label_t l12, label_t l13) {
        mpls_ingress_12_hop(l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12);
        mpls_push(l13, 0, hdr);
    }

    action mpls_ingress_14_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11, label_t l12, label_t l13, label_t l14) {
        mpls_ingress_13_hop(l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13);
        mpls_push(l14, 0, hdr);
    }

    action mpls_ingress_15_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11, label_t l12, label_t l13, label_t l14, label_t l15) {
        mpls_ingress_14_hop(l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14);
        mpls_push(l15, 0, hdr);
    }

    action mpls_ingress_16_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11, label_t l12, label_t l13, label_t l14, label_t l15, label_t l16) {
        mpls_ingress_15_hop(l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15);
        mpls_push(l16, 0, hdr);
    }

    /*
     * This table maps the selected path (identified by the ecmp_group_id and ecmp_hash) to the actual
     * path in the form of a label stack.
     */
    table ecmp_FEC_tbl {
        key = {
            meta.ecmp_group_id: exact;
            meta.ecmp_hash: exact;
        }
        actions = {
            mpls_ingress_1_hop;
            mpls_ingress_2_hop;
            mpls_ingress_3_hop;
            mpls_ingress_4_hop;
            mpls_ingress_5_hop;
            mpls_ingress_6_hop;
            mpls_ingress_7_hop;
            mpls_ingress_8_hop;
            mpls_ingress_9_hop;
            mpls_ingress_10_hop;
            mpls_ingress_11_hop;
            mpls_ingress_12_hop;
            mpls_ingress_13_hop;
            mpls_ingress_14_hop;
            mpls_ingress_15_hop;
            mpls_ingress_16_hop;
            drop;
        }
        default_action = drop;
        size = 256;
    }

    action mpls_forward(macAddr_t dstAddr, egressSpec_t port) {
        // set the src mac address as the previous dst
        // TODO: this is not what happens in reality
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        standard_metadata.egress_spec = port;

        hdr.mpls[1].ttl = hdr.mpls[0].ttl - 1;
        hdr.mpls.pop_front(1);
    }

    action penultimate(macAddr_t dstAddr, egressSpec_t port) {
        // set the src mac address as the previous dst
        // TODO: this is not what happens in reality
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        hdr.ipv4.ttl = hdr.mpls[0].ttl - 1;

        standard_metadata.egress_spec = port;

        // Pop last MPLS header so we need to set new ethernet type
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.mpls.pop_front(1);
    }

    /*
     * This table handles the forwarding of MPLS packets.
     * The handling is slightly different for MPLS egress switches, where the last MPLS header is popped.
     */
    table mpls_tbl {
        key = {
            hdr.mpls[0].label: exact;
            hdr.mpls[0].s: exact;
        }
        actions = {
            mpls_forward;
            penultimate;
            NoAction;
        }
        default_action = NoAction();
        size = CONST_MAX_LABELS * 2;
    }

    action get_tcp_ports() {
        meta.srcPort = hdr.tcp.srcPort;
        meta.dstPort = hdr.tcp.dstPort;
    }

    action get_udp_ports() {
        meta.srcPort = hdr.udp.srcPort;
        meta.dstPort = hdr.udp.dstPort;
    }

    apply {
        // handle non-MPLS packets
        if (hdr.ipv4.isValid() && !hdr.mpls[0].isValid()) {

            // read ports into metadata
            if (hdr.tcp.isValid()) {
                get_tcp_ports();
            } else if (hdr.udp.isValid()) {
                get_udp_ports();
            }

            switch (ipv4_lpm.apply().action_run) {
                ecmp_group: {
                    ecmp_FEC_tbl.apply();
                }
            }
        }

        // handle MPLS packets (note that they may have just become MPLS packets by applying the tables above)
        if (hdr.mpls[0].isValid()) {
            mpls_tbl.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // we decrease the TTL, thus we have to update the IPv4 checksum
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
