/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// Define constants

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MPLS = 0x8847;
const bit<16> TYPE_HEARTBEAT = 0x1234;
const bit<8> PROTOCOL_TCP = 0x6;
const bit<8> PROTOCOL_UDP = 0x11;

#define CONST_MAX_LABELS 11 // LON has 8 base links, plus a maximum of 3 additional links
#define CONST_MAX_MPLS_HOPS 16


// Define headers

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<20> label_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header mpls_t {
    bit<20>   label;
    bit<3>    exp;
    bit<1>    s;
    bit<8>    ttl;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header heartbeat_t {
    bit<9>    port;
    bit<1>    from_cp;
    bit<1>    from_switch_to_cpu;
    bit<1>    link_status;
    bit<4>    padding;
}


// Instantiate metadata fields
struct metadata {
    bit<14> ecmp_hash;
    bit<14> ecmp_group_id;

    bit<16> srcPort;
    bit<16> dstPort;

    // flowlet switching
    bit<48> flowlet_last_stamp;
    bit<48> flowlet_time_diff;
    bit<13> flowlet_register_index;
    bit<16> flowlet_id;

    // heartbeat
    bit<1> linkState;
    bit<1> newLinkState;
    bit<9> affectedPort;
    bit<48> timestamp;


}

// Instantiate packet headers
struct headers {
    ethernet_t   ethernet;
    heartbeat_t  heartbeat;
    mpls_t[CONST_MAX_MPLS_HOPS] mpls;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
}

