/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_INT = 0xFD;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
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

header int_pai_t{
bit<32> Tamanho_Filho;
bit<32> Quantidade_Filhos;
}

header int_filho_t{
bit<32> ID_Switch;
bit<9> Porta_Entrada;
bit<9> Porta_Saida;
bit<48> Timestamp;
//* Another Headers *//
bit<30> padding;
}

struct metadata {
    bit<32> switch_id;
    bit<1> dummy;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    int_pai_t    int_pai;
    int_filho_t[10]  int_filhos;      
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
            
        transition select(hdr.ipv4.protocol) {
            PROTO_INT: parse_int_pai;
            default: accept;
        }
    }

    state parse_int_pai {
        packet.extract(hdr.int_pai);

        transition select(hdr.int_pai.Quantidade_Filhos) {
            0: accept;
            default: parse_int_filhos;
        }
    }

    state parse_int_filhos {
        packet.extract(hdr.int_filhos.next);

        transition select(hdr.int_filhos.lastIndex + 1 < hdr.int_pai.Quantidade_Filhos) 
        {
            true: parse_int_filhos;
            false: accept;
        }
    }
}

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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_switch_id(bit<32> id) {
        meta.switch_id = id;
    }

    table switch_id_table {
        key = {
            meta.dummy : exact;
        }
        actions = {
            set_switch_id;
            NoAction;
        }
        size = 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

apply {
    meta.dummy = 1;
    switch_id_table.apply();

    if (hdr.ipv4.isValid()) {
        ipv4_lpm.apply();
    }

    // INT inicialização (somente uma vez)
    if (!hdr.int_pai.isValid()) {
        hdr.int_pai.setValid();
        hdr.int_pai.Tamanho_Filho = 128;
        hdr.int_pai.Quantidade_Filhos = 0;
        hdr.ipv4.protocol = PROTO_INT;

        // primeiro hop conta como "pai + filho"
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 24;
    } else {
        // hops seguintes
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 16;
    }

    // INT sempre adiciona 1 filho por hop
    hdr.int_filhos.push_front(1);
    hdr.int_filhos[0].setValid();

    hdr.int_filhos[0].ID_Switch = meta.switch_id;
    hdr.int_filhos[0].Porta_Entrada = standard_metadata.ingress_port;
    hdr.int_filhos[0].Porta_Saida = standard_metadata.egress_spec;
    hdr.int_filhos[0].Timestamp = standard_metadata.ingress_global_timestamp;
    hdr.int_filhos[0].padding = 0;

    hdr.int_pai.Quantidade_Filhos = hdr.int_pai.Quantidade_Filhos + 1;
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.int_pai);
        packet.emit(hdr.int_filhos);

    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
