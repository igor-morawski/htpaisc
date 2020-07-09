import socket
import threading
import time
import signal
import struct
import os
import select

import htpaisc.utils

SOCK_TIMEOUT = 1

HTPA_PORT = 30444
BUFF_SIZE = 1300
HTPA32x32d_PACKET1_LEN = 1292
HTPA32x32d_PACKET2_LEN = 1288
HTPA32x32d_BYTE_FORMAT = "<h"  # Little-Endian b

HTPA_CALLING_MSG = "Calling HTPA series devices"
HTPA_BIND_MSG = "Bind HTPA series device"
HTPA_RELEASE_MSG = "x Release HTPA series device"
HTPA_STREAM_MSG = "K"
HTPA_SINGLE_VOLTAGE_FFRAME_MSG = "c"

HTPA32x32d_IDENT_MSG_CHUNK = "I am Arraytype 10"

def validateIP(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def order_packets(a, b):
    """
    Checks if packets are of different lengths and, if yes, orders a pair of packets received.
    Parameters
    ----------
    a, b : packets (buffers)
        A pair of packets containing one frame captured by HTPA 32x32d.
    Returns
    -------
    tuple 
        A pair of ordered packets containing one frame captured by HTPA 32x32d (packet1, packet2).
    """
    packet1 = a if (len(a) == HTPA32x32d_PACKET1_LEN) else b if (
        len(b) == HTPA32x32d_PACKET1_LEN) else None
    packet2 = a if (len(a) == HTPA32x32d_PACKET2_LEN) else b if (
        len(b) == HTPA32x32d_PACKET2_LEN) else None
    return (packet1, packet2)


def decode_packets_to_list(packet1, packet2) -> str:
    """
    Decodes a pair 
    Parameters
    ----------
    packet1, packet2 : packets (buffers)
        A pair of ordered packets containing one frame captured by HTPA 32x32d.
    Returns
    -------
    str 
        Decoded space-delimited temperature values in [1e2 deg. Celsius] (consistent with Heimann's data structure)
    """
    packet = packet1 + packet2
    packet_list = []
    for byte in struct.iter_unpack(HTPA32x32d_BYTE_FORMAT, packet):
        packet_list.append(byte[0])
    return packet_list


class Device:
    """
    Stores HTPA32x32d device's info for UDP communication
    Attributes
    ----------
    ip : str
        IP address of the camera
    port : int
        HTPA port for UDP communication according to the datasheet
    address : tuple
        Device's (ip, port) in an ordered tuple
    """
    def __init__(self, ip, port=None, verbose=False):
        self.verbose = verbose
        self.ip = ip
        if not port:
            self.port = HTPA_PORT
        else:
            self.port = port
        self.address = (self.ip, self.port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', 0))
        self.sock.settimeout(SOCK_TIMEOUT)

    def connect(self):
        htpaisc.utils.print_if_verbose("Connecting to {}...".format(self.ip), self.verbose)
        # Bind
        try:
            self.sock.sendto(HTPA_BIND_MSG.encode(), self.address)
            _ = self.sock.recv(BUFF_SIZE)
            return True
        except socket.timeout:
            htpaisc.utils.print_if_verbose("Could not bind device {}".format(self.ip), self.verbose)
            return False
    
    def release(self):
        try:
            htpaisc.utils.print_if_verbose("Released device {}".format(self.ip), self.verbose)
            self.sock.sendto(HTPA_RELEASE_MSG.encode(), self.address)
            return True
        except socket.timeout:
            htpaisc.utils.print_if_verbose("Could not release device {}".format(self.ip), self.verbose)
            return False


    def capture_voltage_frame(self):
        frame = None
        try:
            self.sock.sendto(HTPA_SINGLE_VOLTAGE_FFRAME_MSG.encode(), self.address)
            packet_a = _ = self.sock.recv(BUFF_SIZE)
            packet_b = _ = self.sock.recv(BUFF_SIZE)
            packets = order_packets(packet_a, packet_b)
            frame = decode_packets_to_list(*packets)
            if -1 in frame:
                frame = None
        except socket.timeout:
            pass #XXX
        return frame
        

class Device_Manager:
    """
    HTPA32x32d device manager
    # TODO: Docs
    """
    def __init__(self, log_dir, bcast_addr, verbose=False):
        self.verbose = verbose
        if not os.path.exists(log_dir):
            os.mkdir(log_dir)
        if not os.access(log_dir, os.W_OK):
            raise Exception("Specified directory is not writeable.")
        self._bcast_addr = bcast_addr
        if not validateIP(self._bcast_addr):
            raise ValueError("Specified broadcasting address ({}) is incorrect.".format(self._bcast_addr))
        self._broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._broadcast_socket.bind(('', 0))
        self._broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._device_addresses_l = []
        self._connected_devices = []

    def _add_device_address(self, addr):
        if addr not in self._device_addresses_l:
            self._device_addresses_l.append(addr)

    def scan(self, duration = 1., timeout = 0.1):
        """
        Scans for HTPA32x32d devices and adds newly discovered devices to the Device Manager. 
        Only 32x32 devices are discovered, other resolutions are ignored.
        Parameters
        ----------
        duration : float
            Scan duration in seconds
        timeout : float
            Socket timeout in seconds
        Returns
        -------
        bool
            True if the scan is finished
        """
        if self.verbose: 
            print("Scanning network...")
        self._broadcast_socket.sendto(HTPA_CALLING_MSG.encode(), (self._bcast_addr, HTPA_PORT))
        
        iteration = 0
        while iteration < duration / timeout:
            ready = select.select([self._broadcast_socket], [], [], timeout)
            if ready[0]:
                data, addr = self._broadcast_socket.recvfrom(BUFF_SIZE)
                if HTPA32x32d_IDENT_MSG_CHUNK in data.decode():
                    htpaisc.utils.print_if_verbose("HTPA32x32d device discovered at {}".format(addr[0]), self.verbose)
                    self._add_device_address(addr)
            iteration += 1
        return True
    
    def _add_connected_device(self, device_obj):
        if device_obj not in self._connected_devices:
            self._connected_devices.append(device_obj)
            htpaisc.utils.print_if_verbose("Added succsesfuly connected device {}".format(device_obj.ip), self.verbose)

    def connect(self):
        """
        Connects to all devices discovered when scanning.
        # TODO
        """
        if not len(self._device_addresses_l):
            raise ValueError("No devices added to the manager. Discover devices by calling 'scan' method.")
        for addr in self._device_addresses_l:
            ip, port =  addr
            d = Device(ip, port, verbose=self.verbose)
            if d.connect():
                self._add_connected_device(d)
    
    def release(self):
        """
        Releases binded HTPA32x32d devices. 
        # TODO
        """
        for d in self._connected_devices:
            d.release()

    def caputre_voltage_frames(self):
        """
        Capture voltage frames from all connected devices.
        Returns
        -------
        list
            List of voltage frames. 
        """
        result = []
        for d in self._connected_devices:
            frame = d.capture_voltage_frame()
            if frame:
                result.append(frame)
        return result


