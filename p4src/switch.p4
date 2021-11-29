/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

// Flowlet switching parameters
#define REGISTER_SIZE 8192
#define TIMESTAMP_WIDTH 48
#define ID_WIDTH 16
#define FLOWLET_TIMEOUT 48w200000

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<ID_WIDTH>>(REGISTER_SIZE) flowlet_to_id;
    register<bit<TIMESTAMP_WIDTH>>(REGISTER_SIZE) flowlet_time_stamp;

    action no_action() {
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    /*
     * Reads the flowlet registers for a tcp flowlet and sets the corresponding metadata fields.
     */
    action read_flowlet_registers_tcp() {

        //compute register index
        hash(meta.flowlet_register_index,
            HashAlgorithm.crc16,
            (bit<16>)0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.ipv4.protocol
            },
            (bit<14>)8192
        );

        // read previous time stamp
        flowlet_time_stamp.read(meta.flowlet_last_stamp, (bit<32>)meta.flowlet_register_index);

        // read previous flowlet id
        flowlet_to_id.read(meta.flowlet_id, (bit<32>)meta.flowlet_register_index);

        // update timestamp
        flowlet_time_stamp.write((bit<32>)meta.flowlet_register_index, standard_metadata.ingress_global_timestamp);
    }

    /*
     * Generates a random flowlet id.
     */
    action get_random_flowlet_id() {
        bit<32> random_t;
        random(random_t, (bit<32>)0, (bit<32>)65000);
        meta.flowlet_id = (bit<16>)random_t;
    }

    /*
     * Generates a random flowlet id and writes it the corresponding register.
     */
    action update_flowlet_id(){
        get_random_flowlet_id();
        flowlet_to_id.write((bit<32>)meta.flowlet_register_index, (bit<16>)meta.flowlet_id);
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
                hdr.ipv4.protocol,
                // add flowlet id as a "salt"
                meta.flowlet_id
            },
            num_nhops
        );

        meta.ecmp_group_id = ecmp_group_id;
    }

    table virtual_circuit {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ecmp_group;
            no_action;
        }
        default_action = no_action;
        size = 256;
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
        hdr.mpls.push_front(1);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l1;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_2_hop(label_t l1, label_t l2) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(2);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l2;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l1;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 1;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_3_hop(label_t l1, label_t l2, label_t l3) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(3);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l3;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l2;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l1;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 1;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_4_hop(label_t l1, label_t l2, label_t l3, label_t l4) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(4);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l4;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l3;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l2;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l1;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 1;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_5_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(5);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l5;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l4;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l3;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l2;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l1;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 1;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_6_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(6);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l6;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l5;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l4;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l3;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l2;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l1;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 1;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_7_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(7);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l7;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l6;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l5;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l4;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l3;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l2;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 0;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[6].setValid();
        hdr.mpls[6].label = l1;
        hdr.mpls[6].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[6].s = 1;
        hdr.mpls[6].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_8_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(8);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l8;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l7;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l6;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l5;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l4;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l3;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 0;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[6].setValid();
        hdr.mpls[6].label = l2;
        hdr.mpls[6].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[6].s = 0;
        hdr.mpls[6].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[7].setValid();
        hdr.mpls[7].label = l1;
        hdr.mpls[7].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[7].s = 1;
        hdr.mpls[7].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_9_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(9);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l9;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l8;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l7;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l6;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l5;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l4;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 0;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[6].setValid();
        hdr.mpls[6].label = l3;
        hdr.mpls[6].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[6].s = 0;
        hdr.mpls[6].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[7].setValid();
        hdr.mpls[7].label = l2;
        hdr.mpls[7].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[7].s = 0;
        hdr.mpls[7].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[8].setValid();
        hdr.mpls[8].label = l1;
        hdr.mpls[8].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[8].s = 1;
        hdr.mpls[8].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_10_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(10);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l10;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l9;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l8;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l7;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l6;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l5;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 0;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[6].setValid();
        hdr.mpls[6].label = l4;
        hdr.mpls[6].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[6].s = 0;
        hdr.mpls[6].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[7].setValid();
        hdr.mpls[7].label = l3;
        hdr.mpls[7].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[7].s = 0;
        hdr.mpls[7].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[8].setValid();
        hdr.mpls[8].label = l2;
        hdr.mpls[8].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[8].s = 0;
        hdr.mpls[8].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[9].setValid();
        hdr.mpls[9].label = l1;
        hdr.mpls[9].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[9].s = 1;
        hdr.mpls[9].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_11_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(11);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l11;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l10;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l9;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l8;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l7;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l6;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 0;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[6].setValid();
        hdr.mpls[6].label = l5;
        hdr.mpls[6].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[6].s = 0;
        hdr.mpls[6].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[7].setValid();
        hdr.mpls[7].label = l4;
        hdr.mpls[7].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[7].s = 0;
        hdr.mpls[7].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[8].setValid();
        hdr.mpls[8].label = l3;
        hdr.mpls[8].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[8].s = 0;
        hdr.mpls[8].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[9].setValid();
        hdr.mpls[9].label = l2;
        hdr.mpls[9].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[9].s = 0;
        hdr.mpls[9].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[10].setValid();
        hdr.mpls[10].label = l1;
        hdr.mpls[10].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[10].s = 1;
        hdr.mpls[10].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_12_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11, label_t l12) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(12);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l12;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l11;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l10;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l9;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l8;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l7;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 0;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[6].setValid();
        hdr.mpls[6].label = l6;
        hdr.mpls[6].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[6].s = 0;
        hdr.mpls[6].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[7].setValid();
        hdr.mpls[7].label = l5;
        hdr.mpls[7].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[7].s = 0;
        hdr.mpls[7].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[8].setValid();
        hdr.mpls[8].label = l4;
        hdr.mpls[8].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[8].s = 0;
        hdr.mpls[8].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[9].setValid();
        hdr.mpls[9].label = l3;
        hdr.mpls[9].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[9].s = 0;
        hdr.mpls[9].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[10].setValid();
        hdr.mpls[10].label = l2;
        hdr.mpls[10].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[10].s = 0;
        hdr.mpls[10].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[11].setValid();
        hdr.mpls[11].label = l1;
        hdr.mpls[11].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[11].s = 1;
        hdr.mpls[11].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_13_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11, label_t l12, label_t l13) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(13);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l13;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l12;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l11;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l10;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l9;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l8;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 0;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[6].setValid();
        hdr.mpls[6].label = l7;
        hdr.mpls[6].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[6].s = 0;
        hdr.mpls[6].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[7].setValid();
        hdr.mpls[7].label = l6;
        hdr.mpls[7].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[7].s = 0;
        hdr.mpls[7].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[8].setValid();
        hdr.mpls[8].label = l5;
        hdr.mpls[8].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[8].s = 0;
        hdr.mpls[8].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[9].setValid();
        hdr.mpls[9].label = l4;
        hdr.mpls[9].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[9].s = 0;
        hdr.mpls[9].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[10].setValid();
        hdr.mpls[10].label = l3;
        hdr.mpls[10].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[10].s = 0;
        hdr.mpls[10].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[11].setValid();
        hdr.mpls[11].label = l2;
        hdr.mpls[11].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[11].s = 0;
        hdr.mpls[11].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[12].setValid();
        hdr.mpls[12].label = l1;
        hdr.mpls[12].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[12].s = 1;
        hdr.mpls[12].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_14_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11, label_t l12, label_t l13, label_t l14) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(14);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l14;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l13;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l12;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l11;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l10;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l9;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 0;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[6].setValid();
        hdr.mpls[6].label = l8;
        hdr.mpls[6].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[6].s = 0;
        hdr.mpls[6].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[7].setValid();
        hdr.mpls[7].label = l7;
        hdr.mpls[7].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[7].s = 0;
        hdr.mpls[7].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[8].setValid();
        hdr.mpls[8].label = l6;
        hdr.mpls[8].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[8].s = 0;
        hdr.mpls[8].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[9].setValid();
        hdr.mpls[9].label = l5;
        hdr.mpls[9].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[9].s = 0;
        hdr.mpls[9].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[10].setValid();
        hdr.mpls[10].label = l4;
        hdr.mpls[10].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[10].s = 0;
        hdr.mpls[10].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[11].setValid();
        hdr.mpls[11].label = l3;
        hdr.mpls[11].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[11].s = 0;
        hdr.mpls[11].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[12].setValid();
        hdr.mpls[12].label = l2;
        hdr.mpls[12].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[12].s = 0;
        hdr.mpls[12].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[13].setValid();
        hdr.mpls[13].label = l1;
        hdr.mpls[13].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[13].s = 1;
        hdr.mpls[13].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_15_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11, label_t l12, label_t l13, label_t l14, label_t l15) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(15);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l15;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l14;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l13;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l12;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l11;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l10;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 0;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[6].setValid();
        hdr.mpls[6].label = l9;
        hdr.mpls[6].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[6].s = 0;
        hdr.mpls[6].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[7].setValid();
        hdr.mpls[7].label = l8;
        hdr.mpls[7].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[7].s = 0;
        hdr.mpls[7].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[8].setValid();
        hdr.mpls[8].label = l7;
        hdr.mpls[8].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[8].s = 0;
        hdr.mpls[8].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[9].setValid();
        hdr.mpls[9].label = l6;
        hdr.mpls[9].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[9].s = 0;
        hdr.mpls[9].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[10].setValid();
        hdr.mpls[10].label = l5;
        hdr.mpls[10].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[10].s = 0;
        hdr.mpls[10].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[11].setValid();
        hdr.mpls[11].label = l4;
        hdr.mpls[11].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[11].s = 0;
        hdr.mpls[11].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[12].setValid();
        hdr.mpls[12].label = l3;
        hdr.mpls[12].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[12].s = 0;
        hdr.mpls[12].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[13].setValid();
        hdr.mpls[13].label = l2;
        hdr.mpls[13].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[13].s = 0;
        hdr.mpls[13].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[14].setValid();
        hdr.mpls[14].label = l1;
        hdr.mpls[14].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[14].s = 1;
        hdr.mpls[14].ttl = hdr.ipv4.ttl - 1;
    }

    action mpls_ingress_16_hop(label_t l1, label_t l2, label_t l3, label_t l4, label_t l5, label_t l6, label_t l7, label_t l8, label_t l9, label_t l10, label_t l11, label_t l12, label_t l13, label_t l14, label_t l15, label_t l16) {
        hdr.ethernet.etherType = TYPE_MPLS;
        hdr.mpls.push_front(16);

        hdr.mpls[0].setValid();
        hdr.mpls[0].label = l16;
        hdr.mpls[0].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[0].s = 0;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[1].setValid();
        hdr.mpls[1].label = l15;
        hdr.mpls[1].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[1].s = 0;
        hdr.mpls[1].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[2].setValid();
        hdr.mpls[2].label = l14;
        hdr.mpls[2].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[2].s = 0;
        hdr.mpls[2].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[3].setValid();
        hdr.mpls[3].label = l13;
        hdr.mpls[3].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[3].s = 0;
        hdr.mpls[3].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[4].setValid();
        hdr.mpls[4].label = l12;
        hdr.mpls[4].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[4].s = 0;
        hdr.mpls[4].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[5].setValid();
        hdr.mpls[5].label = l11;
        hdr.mpls[5].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[5].s = 0;
        hdr.mpls[5].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[6].setValid();
        hdr.mpls[6].label = l10;
        hdr.mpls[6].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[6].s = 0;
        hdr.mpls[6].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[7].setValid();
        hdr.mpls[7].label = l9;
        hdr.mpls[7].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[7].s = 0;
        hdr.mpls[7].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[8].setValid();
        hdr.mpls[8].label = l8;
        hdr.mpls[8].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[8].s = 0;
        hdr.mpls[8].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[9].setValid();
        hdr.mpls[9].label = l7;
        hdr.mpls[9].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[9].s = 0;
        hdr.mpls[9].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[10].setValid();
        hdr.mpls[10].label = l6;
        hdr.mpls[10].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[10].s = 0;
        hdr.mpls[10].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[11].setValid();
        hdr.mpls[11].label = l5;
        hdr.mpls[11].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[11].s = 0;
        hdr.mpls[11].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[12].setValid();
        hdr.mpls[12].label = l4;
        hdr.mpls[12].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[12].s = 0;
        hdr.mpls[12].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[13].setValid();
        hdr.mpls[13].label = l3;
        hdr.mpls[13].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[13].s = 0;
        hdr.mpls[13].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[14].setValid();
        hdr.mpls[14].label = l2;
        hdr.mpls[14].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[14].s = 0;
        hdr.mpls[14].ttl = hdr.ipv4.ttl - 1;

        hdr.mpls[15].setValid();
        hdr.mpls[15].label = l1;
        hdr.mpls[15].ttl = CONST_MAX_MPLS_HOPS;
        hdr.mpls[15].s = 1;
        hdr.mpls[15].ttl = hdr.ipv4.ttl - 1;
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

    table virtual_circuit_path {
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

                @atomic {
                    read_flowlet_registers_tcp();
                    meta.flowlet_time_diff = standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp;

                    // check if a new flowlet starts
                    if (meta.flowlet_time_diff > FLOWLET_TIMEOUT){
                        update_flowlet_id();
                    }
                }

            } else if (hdr.udp.isValid()) {
                get_udp_ports();

                // every UDP packet is its own "flowlet", so we generate a new id
                get_random_flowlet_id();

            } else {
                // avoid undefined behavior (e.g., for ICMP packets)
                meta.srcPort = 0;
                meta.dstPort = 0;
                get_random_flowlet_id();
            }

            switch (virtual_circuit.apply().action_run) {
                ecmp_group: {
                    virtual_circuit_path.apply();
                }
                no_action: {
                    switch (ipv4_lpm.apply().action_run) {
                        ecmp_group: {
                            ecmp_FEC_tbl.apply();
                        }
                    }
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
