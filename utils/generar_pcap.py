import struct
import time

# Volcado hexadecimal de una trama CSI capturada
log_hex = """
0000: ffff ffff ffff 4e45 584d 4f4e 0800 4500
0010: 012e 0001 0000 0111 a4ab 0a0a 0a0a ffff
0020: ffff 157c 157c 011a 0000 1111 ea88 a408
0030: f5ee 2b06 a0d9 0000 0110 6500 c11f 3e08
0040: e901 d100 0002 8500 0902 5400 f601 2e00
0050: f501 ebff ee01 b2ff d601 94ff b901 55ff
0060: 9701 33ff 7301 05ff 4b01 dffe 1301 c0fe
0070: d900 b0fe a200 94fe 6700 9ffe 3000 93fe
0080: eeff abfe beff aafe 85ff d5fe 4dff f9fe
0090: 13ff 31ff e8fe 7aff d4fe cdff d8fe 3f00
00a0: f7fe 9e00 4bff f300 0200 2001 0628 0033
00b0: b0ea 8080 8000 0000 0000 0000 d7f7 12fc
00c0: 1610 20f4 e80b f11b 07ec edf3 1002 f000
00d0: 3402 6eff 8b01 65fe a900 cefd adff c7fd
00e0: ecfe 02fe 5dfe 7bfe 17fe ebfe dbfd 7bff
00f0: bbfd 0300 d1fd 6500 fbfd e400 0efe 4801
0100: 42fe 9601 8ffe df01 dbfe 1602 35ff 3c02
0110: 7cff 4302 d7ff 5b02 2f00 5302 8200 5902
0120: c600 3c02 0401 1002 4801 e301 6001 c201
0130: 9201 8d01 b201 5501 d101 2801
"""

def reconstruir_pcap(texto_hex, archivo_salida):
    bytes_paquete = bytearray()
    for linea in texto_hex.strip().split('\n'):
        if ':' in linea:
            contenido_hex = linea.split(':')[1].replace(' ', '')
            bytes_paquete.extend(bytes.fromhex(contenido_hex))

    longitud_trama = len(bytes_paquete)

    pcap_global_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    timestamp_segundos = int(time.time())
    timestamp_microsegundos = 908666
    pcap_packet_header = struct.pack('<IIII', timestamp_segundos, timestamp_microsegundos, longitud_trama, longitud_trama)

    with open(archivo_salida, 'wb') as f:
        f.write(pcap_global_header)
        f.write(pcap_packet_header)
        f.write(bytes_paquete)

    print(f"¡Éxito! Archivo binario '{archivo_salida}' generado ({longitud_trama} bytes de payload).")

if __name__ == "__main__":
    reconstruir_pcap(log_hex, "csi_test.pcap")
