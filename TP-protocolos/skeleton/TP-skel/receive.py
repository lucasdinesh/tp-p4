#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    IP,
    Packet,
    BitField,
    IntField,
    bind_layers,
    get_if_list,
    sniff
)

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

# 1. Definindo o Cabeçalho INT Pai baseado no seu P4
class IntPai(Packet):
    name = "IntPai"
    fields_desc = [
        IntField("Tamanho_Filho", 128),
        IntField("Quantidade_Filhos", 0)
    ]

# 2. Definindo o Cabeçalho INT Filho baseado no seu P4
# Usamos BitField para os tamanhos exatos (9, 9, 48, 30 bits)
class IntFilho(Packet):
    name = "IntFilho"
    fields_desc = [
        IntField("ID_Switch", 0),
        BitField("Porta_Entrada", 0, 9),
        BitField("Porta_Saida", 0, 9),
        BitField("Timestamp", 0, 48),
        BitField("padding", 0, 30)
    ]

# 3. A "Mágica" do Bind (Amarrando as camadas)
# Se o IP tiver protocolo 253, a próxima camada é o IntPai
bind_layers(IP, IntPai, proto=253)

# Se houver um IntPai, a próxima camada PODE ser um IntFilho
bind_layers(IntPai, IntFilho)

# Se houver um IntFilho, a próxima camada PODE ser outro IntFilho (empilhamento)
bind_layers(IntFilho, IntFilho)


def handle_pkt(pkt):
    # Agora procuramos pelo NOSSO cabeçalho em vez de TCP
    if IntPai in pkt:
        print("\n" + "="*40)
        print(" PACOTE COM TELEMETRIA (INT) RECEBIDO!")
        print("="*40)
        
        # O método show() vai imprimir a árvore do pacote decodificada
        pkt.show()
        sys.stdout.flush()

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    if not ifaces:
        print("Nenhuma interface eth encontrada.")
        exit(1)
        
    iface = ifaces[0]
    print(f"Sniffing na interface {iface} aguardando pacotes INT...")
    sys.stdout.flush()
    
    sniff(iface=iface, prn=lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()