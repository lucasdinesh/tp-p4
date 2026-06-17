/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
// Protocolo customizado para indicar a presença de telemetria INT
const bit<8> PROTO_INT = 0xFD; // 253

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

// --- ALTERAÇÃO: CABEÇALHO PAI (12 bytes no total) ---
header int_pai_t {
    bit<32> Tamanho_Filho;
    bit<32> Quantidade_Filhos;
    
    // Salva o protocolo original (ex: TCP=6, UDP=17) para permitir a reconstrução 
    // do pacote pelo script receive.py (Atende ao critério de separar o payload).
    bit<8>  proto_original; 
    
    // Flag do Requisito Bônus de MTU: 0 = Normal, 1 = Estouro de MTU (> 1500 bytes)
    bit<1>  estouro_mtu;
    
    // Reduzido para 23 bits para fechar exatos 32 bits junto com proto_original e estouro_mtu
    bit<23> padding;        
}

// --- CABEÇALHO FILHO (16 bytes no total) ---
header int_filho_t {
    bit<32> ID_Switch;
    bit<9>  Porta_Entrada;
    bit<9>  Porta_Saida;
    bit<48> Timestamp;
    bit<30> padding;
}

struct metadata {
    bit<32> switch_id;
    bit<1>  dummy;
}

struct headers {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    int_pai_t        int_pai;
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
            
        // Se o protocolo do IP for 253, sabemos que tem telemetria e chamamos o parse_int_pai
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

        // Loop no parser: continua extraindo filhos até atingir a Quantidade_Filhos anotada no Pai
        transition select(hdr.int_filhos.lastIndex + 1 < hdr.int_pai.Quantidade_Filhos) 
        {
            true: parse_int_filhos;
            false: accept;
        }
    }
}

/*************************************************************************
************ C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
************** I N G R E S S   P R O C E S S I N G   *******************
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
            // Executa o roteamento L3 padrão
            ipv4_lpm.apply();
            
            // --- ALTERAÇÃO: BYPASS DO PING ---
            // Se o protocolo for 1 (ICMP), ignoramos a lógica INT. 
            // Isso garante que o comando 'pingall' do Mininet funcione com 100% de sucesso.
            if (hdr.ipv4.protocol != 1) {
                
                // Variável para calcular o peso extra do cabeçalho | standard_metadata.packet_length é bit<32>
                bit<32> tamanho_adicional = 0;
                
                // O primeiro switch injeta Pai (12 bytes) + Filho (16 bytes) = 28 bytes
                // Switches seguintes injetam apenas o Filho = 16 bytes
                if (!hdr.int_pai.isValid()) {
                    tamanho_adicional = 28; 
                } else {
                    tamanho_adicional = 16; 
                }

                // --- ALTERAÇÃO: REQUISITO BÔNUS (LIMITE DE MTU) ---
                // Verifica se o tamanho real do pacote no cabo + a nossa telemetria respeitam os 1500 bytes
                if (standard_metadata.packet_length + tamanho_adicional <= 1500) {
                    
                    // Inicia o cabeçalho Pai se for o primeiro salto
                    if (!hdr.int_pai.isValid()) {
                        hdr.int_pai.setValid();
                        hdr.int_pai.Tamanho_Filho = 128; // Tamanho em bits de um filho
                        hdr.int_pai.Quantidade_Filhos = 0;
                        
                        // Salva o protocolo de transporte original antes de sobrescrever com 253
                        hdr.int_pai.proto_original = hdr.ipv4.protocol;
                        hdr.int_pai.estouro_mtu = 0; // Inicia a flag do MTU em falso
                        hdr.ipv4.protocol = PROTO_INT; // Avisa a rede que este é um pacote INT
                    }

                    // Faz o cast explícito para 16 bits exigido pela arquitetura do IPv4
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)tamanho_adicional;

                    // Empurra a pilha de filhos e insere os dados de telemetria do nó atual
                    hdr.int_filhos.push_front(1);
                    hdr.int_filhos[0].setValid();
                    hdr.int_filhos[0].ID_Switch = meta.switch_id;
                    hdr.int_filhos[0].Porta_Entrada = standard_metadata.ingress_port;
                    hdr.int_filhos[0].Porta_Saida = standard_metadata.egress_spec;
                    hdr.int_filhos[0].Timestamp = standard_metadata.ingress_global_timestamp;
                    hdr.int_filhos[0].padding = 0;

                    hdr.int_pai.Quantidade_Filhos = hdr.int_pai.Quantidade_Filhos + 1;
                    
                } else {
                    // --- ALTERAÇÃO: ESTOURO DE MTU DETECTADO ---
                    // O pacote bateria no MTU. Se ele já tiver telemetria iniciada, nós apenas 
                    // levantamos a flag de alerta, mas NÃO adicionamos nosso salto para não corromper o pacote.
                    if (hdr.int_pai.isValid()) {
                        hdr.int_pai.estouro_mtu = 1;
                    }
                }
            }
        }
    }
}

/*************************************************************************
**************** E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
************* C H E C K S U M    C O M P U T A T I O N   **************
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
*********************** D E P A R S E R  *******************************
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
*********************** S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;