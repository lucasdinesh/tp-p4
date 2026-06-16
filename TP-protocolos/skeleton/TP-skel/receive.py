#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    IP, TCP, UDP, ICMP, Raw, Packet, BitField, IntField, 
    PacketListField, bind_layers, get_if_list, sniff
)

def get_if():
    ifs = get_if_list()
    iface = None
    for i in ifs:
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IntFilho(Packet):
    name = "IntFilho"
    fields_desc = [
        IntField("ID_Switch", 0),
        BitField("Porta_Entrada", 0, 9),
        BitField("Porta_Saida", 0, 9),
        BitField("Timestamp", 0, 48),
        BitField("padding", 0, 30)
    ]
    
    def extract_padding(self, s):
        return "", s

class IntPai(Packet):
    name = "IntPai"
    fields_desc = [
        IntField("Tamanho_Filho", 128),
        IntField("Quantidade_Filhos", 0),
        BitField("proto_original", 0, 8),
        BitField("estouro_mtu", 0, 1), 
        BitField("padding", 0, 23),      
        PacketListField("Filhos", [], IntFilho, count_from=lambda pkt: pkt.Quantidade_Filhos)
    ]

bind_layers(IP, IntPai, proto=253)


def handle_pkt(pkt):
    if IntPai in pkt:
        
        if pkt.haslayer("ICMP"):
            return

        print("\n" + "="*55)
        print("    [+] PACOTE COM TELEMETRIA (INT) RECEBIDO!")
        print("="*55)
        
        int_pai = pkt[IntPai]
        print(f" > Protocolo L4 Original: {int_pai.proto_original}")
        print(f" > Quantidade de Saltos:  {int_pai.Quantidade_Filhos}")
        
        # --- LÓGICA DO ALERTA DE MTU ---
        if int_pai.estouro_mtu == 1:
            print("\n [!!!] ALERTA DE REDE: Estouro de MTU (1500 bytes) detectado!")
            print("       Alguns switches não puderam inserir telemetria.")
            print("       O caminho apresentado abaixo está INCOMPLETO.")
        else:
            print("\n [OK] Status do MTU: Saudável. Todos os dados foram coletados.")
        # -------------------------------

        filhos_reversos = list(reversed(int_pai.Filhos))
        
        print("\n--- Caminho Percorrido ---")
        for i, filho in enumerate(filhos_reversos):
            print(f" Salto {i+1}: Switch ID = {filho.ID_Switch} | Porta In: {filho.Porta_Entrada} -> Porta Out: {filho.Porta_Saida} | Timestamp: {filho.Timestamp}")
        
        if Raw in pkt:
            bytes_brutos = pkt[Raw].load
            proto_salvo = int_pai.proto_original
            
            try:
                # O Python usa a informação que você salvou no Switch!
                pacote_recuperado = None
                if proto_salvo == 6:
                    pacote_recuperado = TCP(bytes_brutos)
                    nome_proto = "TCP"
                elif proto_salvo == 17:
                    pacote_recuperado = UDP(bytes_brutos)
                    nome_proto = "UDP"
                elif proto_salvo == 1:
                    pacote_recuperado = ICMP(bytes_brutos)
                    nome_proto = "ICMP"
                
                if pacote_recuperado:
                    print(f"\n--- Payload Original ({nome_proto}) ---")
                    # Se tiver mensagem embutida no TCP/UDP/ICMP, tenta imprimir:
                    if Raw in pacote_recuperado:
                        mensagem = pacote_recuperado[Raw].load.decode('utf-8', errors='ignore')
                        print(f" Mensagem: {mensagem}")
                    else:
                        print(" (Pacote vazio sem mensagem de texto)")
                        
            except Exception as e:
                print(f"\n[!] Erro ao reconstruir payload original: {e}")

        print("="*55)
        sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    if not ifaces:
        print("Nenhuma interface eth encontrada.")
        exit(1)
        
    iface = ifaces[0]
    print(f"Iniciando sniffer na interface {iface} aguardando tráfego INT...")
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()