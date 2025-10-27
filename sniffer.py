from scapy.all import conf, Ether, srp, sr1, IP, TCP, ICMP, ARP
import platform, ipaddress

import time, subprocess, sys
import warnings

conf.verb = 0
warnings.filterwarnings("ignore", category=SyntaxWarning)

#FUNCOES UTILITARIAS-----------------

# INTERFACE ATIVA
def interface_ativa():
    try:
        interface, ip_local, gateway = conf.route.route('0.0.0.0')
        return {
         'gateway':     gateway if gateway != '0.0.0.0' else None,
         'ip_local':    ip_local,
         'interface':   interface   
        }
    except Exception as e:
        return {
            'gateway':  None,
            'ip_local': None
        }    
    
# INTERFACES MAQUINA LOCAL
def interfaces_locais():
    interfaces_lan = []
    interfaces_virtuais = []
    
    for iface in conf.ifaces.values():
        if iface.name.split(' ')[0] == 'Wi-Fi' or iface.name.split(' ')[0] == 'Ethernet' or iface.name.split(' ')[1] == 'Wi-Fi' or iface.name.split(' ')[1] == 'Ethernet':
            info = {
                'esta_ativa':   True,
                'interface':    iface.name,
                'dispositivo':  getattr(iface, 'description', None),
                'ip':           getattr(iface, 'ip', None),
                'mac':          getattr(iface, 'mac', None)
            }
            if info['ip'].split('.')[0] == '169' or info['ip'].split('.')[0] == '0' or info['ip'].split('.')[0] == '127':
                info['esta_ativa'] = False
            interfaces_lan.append(info)
        else:
            if iface.description.split(' ')[0] == 'WAN' or iface.description.split(' ')[1] == 'WAN':
                pass
            info2 = {
                'dispositivo':  getattr(iface, 'description', None),
                'ip':           getattr(iface, 'ip', None),
                'mac':          getattr(iface, 'mac', None)
            }
            interfaces_virtuais.append(info2)

    print('INTERFACES LAN:')
    for i, info in enumerate(interfaces_lan):
        if info['esta_ativa']:
            print(f'{info['interface']} -> {info['dispositivo']} \n     IP: {info['ip']:15} - MAC: {info['mac']} ***ATIVA')
        else:
            print(f'{info['interface']} -> {info['dispositivo']} \n     IP: {info['ip']:15} - MAC: {info['mac']}')

    print('-'*20 + '\nINTERFACES VIRTUAIS:')
    for i, info in enumerate(interfaces_virtuais):
        print(f'{info2['dispositivo']} -> IP: {info['ip']:15} - MAC: {info2['mac']}')
    
    return interfaces_lan, interfaces_virtuais

# HOSTS (INTERFACES) EXTERNOS À MAQUINA LOCAL (MESMA REDE)
def interfaces_lan(timeout=3, ports=None, ip_origem=None, interface_origem=None):
    if ports is None:
        ports = [22, 80, 443, 53, 139, 445, 3389, 8080]
    
    try:
        rede = ipaddress.IPv4Network(f"{ip_origem}/24", strict=False)
    except Exception:
        print("Erro ao calcular a sub-rede. Abortando.")

    pacote = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(rede))
    answered, _ = srp(pacote, timeout=timeout, iface=interface_origem, verbose=False)

    hosts = []
    for snd, rcv in answered:
        dados={
            'host_ip' :  rcv.psrc,
            'host_mac' :  rcv.hwsrc,
            'ttl' : None,
            'os_guess' : "Desconhecido"}

        try:
            icmp_resp = sr1(IP(dst=dados['host_ip'])/ICMP(), timeout=1, iface=interface_origem, verbose=False)
            if icmp_resp is not None:
                dados['ttl'] = getattr(icmp_resp, 'ttl', None)
        except Exception:
            dados['ttl'] = None

        if dados['ttl'] is not None:
            if      dados['ttl'] >= 200:
                dados['os_guess'] = "Equipamento de rede (Cisco/Outros)"
            elif    dados['ttl'] >= 128:
                dados['os_guess'] = "Windows (palpite)"
            elif    dados['ttl'] >= 64:
                dados['os_guess'] = "Linux/Unix/BSD (palpite)"
            else:
                dados['os_guess'] = "Desconhecido/Dispositivo pequeno"

        hosts.append(dados)
    if hosts:
        print('HOSTS ENCONTRADOS:')
        for h in hosts:
            print(f'{h['host_ip']:15} - {h['host_mac']:17} - TTL:{h['ttl']} OS:{h['os_guess']}')


#INTERFACE CMD------------
if __name__ == '__main__':
    try:
        interface_nivel_ativa =     interface_ativa()
        print(f"Gateway: {interface_nivel_ativa['gateway']}\nIP Local: {interface_nivel_ativa['ip_local']}")
        interfaces_nivel_local =    interfaces_locais()
        interfaces_nivel_lan =      interfaces_lan(ip_origem=interface_nivel_ativa['ip_local'], 
                                                   interface_origem=interface_nivel_ativa['interface'])
    except KeyboardInterrupt:
        sys.exit(0)

# print(f'{platform.system()} {platform.version()}')
# print(f"Gateway: {'gateway'}\nIP Local: {'ip_local'}")
# print('-'*50+ '\n')