import socket
from scapy.all import *
import requests
from colorama import Fore, Style

def arp_ping(network):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=False)
    ips = [rcv.psrc for _, rcv in ans]
    ips = list(set(ips))  # Eliminar IPs duplicadas
    for _, rcv in ans:
        print("IP:", Fore.CYAN + rcv.psrc + Style.RESET_ALL, "- MAC:", Fore.YELLOW + rcv.hwsrc + Style.RESET_ALL)
    return ips

def tcp_ping(ip, port):
    try:
        socket.create_connection((ip, port), timeout=2)
        print(f"El TCP Ping ha funcionado con {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL}")
    except socket.error:
        print(f"El TCP Ping ha fallado con {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL}")

def udp_ping(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b"ping", (ip, port))
        data, addr = sock.recvfrom(1024)
        print(f"El UDP Ping ha funcionado con {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL}")
    except socket.error:
        print(f"El UDP Ping ha fallado con {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL}")

def icmp_ping(ip):
    try:
        ans, _ = sr(IP(dst=ip)/ICMP(), timeout=2, verbose=False)
        if ans:
            print(f"El ICMP Ping ha funcionado con {Fore.CYAN}{ip}{Style.RESET_ALL}")
        else:
            print(f"El ICMP Ping ha fallado con {Fore.CYAN}{ip}{Style.RESET_ALL}")
    except:
        print(f"El ICMP Ping ha fallado con {Fore.CYAN}{ip}{Style.RESET_ALL}")

def tcp_connect_scan(ip, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"El puerto {port} esta abierto", Fore.GREEN + "(Abierto)" + Style.RESET_ALL)
            else:
                print(f"El puerto {port} esta cerrado", Fore.RED + "(Cerrado)" + Style.RESET_ALL)
            sock.close()
        except:
            print(f"ha fallado con scan port {port}", Fore.YELLOW + "(Error)" + Style.RESET_ALL)
    return open_ports

def ack_scan(ip, port):
    try:
        ans = sr1(IP(dst=ip)/TCP(dport=port, flags="A"), timeout=2, verbose=False)
        if ans and ans.haslayer(TCP) and ans.getlayer(TCP).flags == 4:  # 4 es el valor del RST flag
            print(f"El puerto {Fore.CYAN}{port}{Style.RESET_ALL} esta siendo filtrado por un firewall")
        else:
            print(f"El puerto {Fore.CYAN}{port}{Style.RESET_ALL} no esta siendo filtrado por ningun firewall")
    except:
        print(f"Ha fallado con el escaneo ACK en el puerto {port}", Fore.YELLOW + "(Error)" + Style.RESET_ALL)

def banner_grabbing(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        print(f"Banner en {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL} - {Fore.GREEN}{banner}{Style.RESET_ALL}")
        sock.close()
    except:
        print(f"Ha fallado el grab banner en el puerto {Fore.CYAN}{port}{Style.RESET_ALL}", Fore.YELLOW + "(Error)" + Style.RESET_ALL)

def http_header_evaluation(ip, port):
    try:
        url = f"http://{ip}:{port}"
        response = requests.head(url, timeout=2)
        if response.status_code == 200:
            server_header = response.headers.get("Server")
            if server_header:
                print(f"Version {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL} - {Fore.GREEN}{server_header}{Style.RESET_ALL}")
            else:
                print(f"Version del servidor no encontrada {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL}")
        else:
            print(f"HTTP request ha fallado en {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL} - Codigo de estado: {response.status_code}")
    except Exception as e:
        print(f"ha fallado con perform HTTP Header Evaluation on port {Fore.CYAN}{port}{Style.RESET_ALL}", Fore.YELLOW + f"(Error: {e})" + Style.RESET_ALL)

def detect_os(ip):
    try:
        ans, _ = sr(IP(dst=ip)/ICMP(), timeout=2, verbose=False)
        if ans:
            ttl = ans[0][1].ttl
            if ttl <= 64:
                print(f"{Fore.CYAN}{ip}{Style.RESET_ALL} - Sistema Operativo: {Fore.GREEN}Linux{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}{ip}{Style.RESET_ALL} - Sistema Operativo: {Fore.GREEN}Windows{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}{ip}{Style.RESET_ALL} - No se pudo detectar el Sistema Operativo")
    except:
        print(f"{Fore.CYAN}{ip}{Style.RESET_ALL} - No se pudo detectar el Sistema Operativo")

def service_fingerprinting(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        print(f"Fingerprinting en {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL} - {Fore.GREEN}{banner}{Style.RESET_ALL}")
        sock.close()
    except:
        print(f"No se pudo realizar el servicio de fingerprinting en el puerto {Fore.CYAN}{port}{Style.RESET_ALL}", Fore.YELLOW + "(Error)" + Style.RESET_ALL)

def user_enumeration(ip, port):
    try:
        url = f"http://{ip}:{port}/"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            users = re.findall(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', response.text)
            if users:
                users = list(set(users))
                print(f"Usuarios enumerados en {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL}: {Fore.GREEN}{users}{Style.RESET_ALL}")
            else:
                print(f"No se encontraron usuarios en {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL}")
        else:
            print(f"La solicitud HTTP falló en {Fore.CYAN}{ip}{Style.RESET_ALL}:{Fore.CYAN}{port}{Style.RESET_ALL} - Status Code: {response.status_code}")
    except Exception as e:
        print(f"No se pudo realizar la enumeración de usuarios en el puerto {Fore.CYAN}{port}{Style.RESET_ALL}", Fore.YELLOW + f"(Error: {e})" + Style.RESET_ALL)

def run_all_options(scanned_ips, ports_to_scan):
    ips = arp_ping(network)
    scanned_ips.extend(ips)
    scanned_ips = list(set(scanned_ips))

    for ip in ips:
        print(Fore.MAGENTA + f"\n==== Ping para {ip} ====" + Style.RESET_ALL)
        tcp_ping(ip, 80)
        udp_ping(ip, 53)
        icmp_ping(ip)

    for ip in scanned_ips:
        print(Fore.MAGENTA + f"\n==== Enumerando puertos abiertos en {ip} ====" + Style.RESET_ALL)
        open_ports = tcp_connect_scan(ip, ports_to_scan)
        print(f"Open ports on {Fore.CYAN}{ip}{Style.RESET_ALL}: {Fore.GREEN}{open_ports}{Style.RESET_ALL}")

    for ip in scanned_ips:
        print(Fore.MAGENTA + "\n==== Descubriendo si algún elemento está filtrando puertos ====" + Style.RESET_ALL)
        print(Fore.MAGENTA + f"\n==== Realizando ACK Scan en {ip} ====" + Style.RESET_ALL)
        for port in ports_to_scan:
            ack_scan(ip, port)

    for ip in scanned_ips:
        print(Fore.MAGENTA + "\n==== Realizando Técnicas de banner grabbing ====" + Style.RESET_ALL)
        print(Fore.MAGENTA + f"\n==== Realizando Banner Grabbing en {ip} ====" + Style.RESET_ALL)
        for port in ports_to_scan:
            banner_grabbing(ip, port)

    for ip in scanned_ips:
        print(Fore.MAGENTA + "\n==== Realizando Evaluación de cabeceras HTTP ====" + Style.RESET_ALL)
        print(Fore.MAGENTA + f"\n==== Realizando HTTP Header Evaluation en {ip} ====" + Style.RESET_ALL)
        for port in ports_to_scan:
            http_header_evaluation(ip, port)

    for ip in scanned_ips:
        print(Fore.MAGENTA + "\n==== Detectando Sistema Operativo ====" + Style.RESET_ALL)
        detect_os(ip)

    for ip in scanned_ips:
        print(Fore.MAGENTA + "\n==== Realizando Fingerprinting de Servicios ====" + Style.RESET_ALL)
        print(Fore.MAGENTA + f"\n==== Realizando Service Fingerprinting en {ip} ====" + Style.RESET_ALL)
        for port in ports_to_scan:
            service_fingerprinting(ip, port)

    for ip in scanned_ips:
        print(Fore.MAGENTA + "\n==== Realizando Enumeración de Usuarios ====" + Style.RESET_ALL)
        print(Fore.MAGENTA + f"\n==== Realizando User Enumeration en {ip} ====" + Style.RESET_ALL)
        for port in ports_to_scan:
            user_enumeration(ip, port)



if __name__ == "__main__":
    network = input("Introduce la red local(e.g., 192.168.1.0/24): ")
    ports_to_scan = [21, 22, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 162, 179, 389, 427, 443, 465, 514, 520, 587, 636, 993, 995, 1194, 1701, 1723, 3306, 3389, 8080]  # Puertos mas comunes
    scanned_ips = []

    while True:
        print(Fore.MAGENTA + "\n==== Menu ====" + Style.RESET_ALL)
        print("1. Realizar pings (ARP, TCP, UDP, ICMP)")
        print("2. Enumerar puertos abiertos (TCP Connect Scan)")
        print("3. Descubrir si algún elemento está filtrando puertos (ACK Scan)")
        print("4. Técnicas de banner grabbing (Banner Grabbing)")
        print("5. Evaluación de cabeceras HTTP para obtener versiones de software (HTTP Header Evaluation)")
        print("6. Detección del sistema operativo")
        print("7. Fingerprinting de Servicios (Service Fingerprinting)")
        print("8. Enumeración de Usuarios (User Enumeration)")
        print("9. Todas las opciones anteriores a la vez")
        print("0. Salir")
        choice = input("Elije una opción (0-9): ")

        if choice == "1":
            ips = arp_ping(network)
            scanned_ips.extend(ips)
            scanned_ips = list(set(scanned_ips))  # Eliminar IPs duplicadas

            for ip in ips:
                print(Fore.MAGENTA + f"\n==== Ping para {ip} ====" + Style.RESET_ALL)
                tcp_ping(ip, 80)
                udp_ping(ip, 53)
                icmp_ping(ip)

        elif choice == "2":
            if not scanned_ips:
                print("Debes ejecutar la opción 1 primero para obtener las IPs.")
            else:
                for ip in scanned_ips:
                    print(Fore.MAGENTA + f"\n==== Enumerando puertos abiertos en {ip} ====" + Style.RESET_ALL)
                    open_ports = tcp_connect_scan(ip, ports_to_scan)
                    print(f"Puertos abiertos en{Fore.CYAN}{ip}{Style.RESET_ALL}: {Fore.GREEN}{open_ports}{Style.RESET_ALL}")
        elif choice == "3":
            if not scanned_ips:
                print("Debes ejecutar la opción 1 primero para obtener las IPs.")
            else:
                print(Fore.MAGENTA + "\n==== Descubriendo si algún elemento está filtrando puertos ====" + Style.RESET_ALL)
                for ip in scanned_ips:
                    print(Fore.MAGENTA + f"\n==== Realizando ACK Scan en {ip} ====" + Style.RESET_ALL)
                    for port in ports_to_scan:
                        ack_scan(ip, port)
        elif choice == "4":
            if not scanned_ips:
                print("Debes ejecutar la opción 1 primero para obtener las IPs.")
            else:
                print(Fore.MAGENTA + "\n==== Realizando Técnicas de banner grabbing ====" + Style.RESET_ALL)
                for ip in scanned_ips:
                    print(Fore.MAGENTA + f"\n==== Realizando Banner Grabbing en {ip} ====" + Style.RESET_ALL)
                    for port in ports_to_scan:
                        banner_grabbing(ip, port)
        elif choice == "5":
            if not scanned_ips:
                print("Debes ejecutar la opción 1 primero para obtener las IPs.")
            else:
                print(Fore.MAGENTA + "\n==== Realizando Evaluación de cabeceras HTTP ====" + Style.RESET_ALL)
                for ip in scanned_ips:
                    print(Fore.MAGENTA + f"\n==== Realizando HTTP Header Evaluation en {ip} ====" + Style.RESET_ALL)
                    for port in ports_to_scan:
                        http_header_evaluation(ip, port)
        elif choice == "6":
            if not scanned_ips:
                print("Debes ejecutar la opción 1 primero para obtener las IPs.")
            else:
                print(Fore.MAGENTA + "\n==== Detectando Sistema Operativo ====" + Style.RESET_ALL)
                for ip in scanned_ips:
                    detect_os(ip)
        elif choice == "7":
            if not scanned_ips:
                print("Debes ejecutar la opción 1 primero para obtener las IPs.")
            else:
                print(Fore.MAGENTA + "\n==== Realizando Fingerprinting de Servicios ====" + Style.RESET_ALL)
                for ip in scanned_ips:
                    print(Fore.MAGENTA + f"\n==== Realizando Service Fingerprinting en {ip} ====" + Style.RESET_ALL)
                    for port in ports_to_scan:
                        service_fingerprinting(ip, port)
        elif choice == "8":
            if not scanned_ips:
                print("Debes ejecutar la opción 1 primero para obtener las IPs.")
            else:
                print(Fore.MAGENTA + "\n==== Realizando Enumeración de Usuarios ====" + Style.RESET_ALL)
                for ip in scanned_ips:
                    print(Fore.MAGENTA + f"\n==== Realizando User Enumeration en {ip} ====" + Style.RESET_ALL)
                    for port in ports_to_scan:
                        user_enumeration(ip, port)
        elif choice == "9":
            if not scanned_ips:
                print("Debes ejecutar la opción 1 primero para obtener las IPs.")
            else:
                run_all_options(scanned_ips, ports_to_scan)
        elif choice == "0":
            print(Fore.MAGENTA + "Saliendo..." + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "Opción inválida. Por favor, elije una opción válida (0-9)." + Style.RESET_ALL)
            