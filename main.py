import socket
import sys
from concurrent.futures import ThreadPoolExecutor


def index(arr: list, key) -> int:
    for i, item in enumerate(arr):
        if item == key:
            return i
    return -1


tcp_ports = list()
udp_ports = list()


def scan_port(ip: str, port: int, only_tcp: bool, only_udp: bool) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)

        response = s.connect_ex((ip, port))

        tcp_port = None
        udp_port = None

        if response == 0:
            tcp_port = port

        try:
            s.sendto(b'', (ip, port))
            data, addr = s.recvfrom(1024)

            udp_port = port
        except socket.timeout:
            pass

        application_protocol = None

        try:
            s.connect((ip, port))
            s.send(b"GET / HTTP/1.1\r\n\r\n")
            data = s.recv(1024)
            s.close()

            if (len(data) > 4) and (b'HTTP' in data):
                application_protocol = 'HTTP'
            elif b'NTP' in data:
                application_protocol = 'NTP'
            elif b'DNS' in data:
                application_protocol = 'DNS'
            elif b'SMTP' in data or b'EHLO' in data:
                application_protocol = 'SMTP'
            elif b'POP3' in data or data.startswith(b'+OK') or data.startswith(b'+'):
                application_protocol = 'POP3'
            elif b'IMAP' in data:
                application_protocol = 'IMAP'
        except ConnectionRefusedError:
            pass
        except PermissionError as e:
            print(f'Error: {e}, port: {port}')
            pass
        except OSError as e:
            print(f'Error: {e}, port: {port}')
            pass

        if only_tcp and (tcp_port is not None):
            tcp_ports.append((tcp_port, application_protocol))
        elif only_udp and (udp_port is not None):
            udp_ports.append((udp_port, application_protocol))


def main():
    argv = sys.argv

    if '-p' not in argv and '--ports' not in argv:
        return 'Вы не ввели диапазон портов'

    portFlagIndex = index(argv, '-p')

    if portFlagIndex == -1:
        portFlagIndex = index(argv, '--ports')

    if '-h' not in argv and '--host' not in argv:
        return 'Вы не IP адрес'

    ipIndex = index(argv, '-h')

    if ipIndex == -1:
        ipIndex = index(argv, '--host')

    startPort = -1
    endPort = -1

    try:
        startPort = int(argv[portFlagIndex + 1])
        endPort = int(argv[portFlagIndex + 2])
    except TypeError:
        return 'Вы ввели неправильный диапазон портов'

    ip = argv[ipIndex]

    if ('-t' not in argv) and ('-u' not in argv):
        return 'Вы не ввели какие парты нужно сканировать'

    only_tcp = '-t' in argv
    only_udp = '-u' in argv

    with ThreadPoolExecutor(max_workers=300) as executor:
        for port in range(startPort, endPort + 1):
            executor.submit(scan_port, ip, port, only_tcp, only_udp)

    for tcp_port in tcp_ports:
        print(f'TCP {tcp_port[0]} {"" if tcp_port[1] is None else tcp_port[1]}')

    for udp_port in udp_ports:
        print(f'UDP {udp_port[0]} {"" if udp_port[1] is None else udp_port[1]}')


if __name__ == '__main__':
    main()
