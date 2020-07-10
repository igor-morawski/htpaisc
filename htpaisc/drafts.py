

    '''
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
    
    def toggle_raw_compensated(self):
        try:
            self.sock.sendto("t".encode(), self.address)
            data = _ = self.sock.recv(BUFF_SIZE)
        except socket.timeout:
            data = None
        return data'''















        import socket
import threading
import time
import signal
import struct
import os
import select
import numpy as np

import threading
import htpaisc.utils


VERBOSE = False

FRAME_DELAY = 0.03
HTPA_MSG_TEMP_SCALING_TO_CELSIUS = 1e-2
MEASURMENT_DURATION_SECONDS = 2.5
ARRAY_DTYPE = np.float32

HTPA_IMG_CROP_START = 4
HTPA_IMG_CROP_END = 28

SOCK_TIMEOUT = 1

MAC_PREFIX = "MAC_"

HTPA_PORT = 30444
BUFF_SIZE = 1300
HTPA32x32d_PACKET1_LEN = 1292
HTPA32x32d_PACKET2_LEN = 1288
HTPA32x32d_BYTE_FORMAT = "<h"  # Little-Endian b


HTPA_CALLING_MSG = "Calling HTPA series devices"
HTPA_BIND_MSG = "Bind HTPA series device"
HTPA_RELEASE_MSG = "x Release HTPA series device"
HTPA_STREAM_MSG = "K"
HTPA_EEDATA_OUT_MSG = "h"
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


def decode_packets_to_list(packet1, packet2) -> list:
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

class Logger_Exit(Exception):
    """
    Custom exception which is used to trigger the clean exit
    of all running threads and the main program.
    """
    def __init__(self, device=None):
        if device:
            device.release()

def decode_packets_to_str(packet1, packet2) -> str:
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
    packet_txt = ""
    for byte in struct.iter_unpack(HTPA32x32d_BYTE_FORMAT, packet):
        packet_txt += str(byte[0]) + " "
    return packet_txt


class Temperature_Logger(threading.Thread):
    """
    Logs temperature # TODO DOCS
    """
    def __init__(self, device, log_dir):
        threading.Thread.__init__(self)
        self.shutdown_flag = threading.Event()
        self.device = device
        self.fp = os.path.join(log_dir, "{}{}.log".format(MAC_PREFIX, self.device.mac.replace(".","-")))
        # start streaming
        self.device.sock.sendto(HTPA_STREAM_MSG.encode(), self.device.address)
        # write an empty log file
        with open(self.fp, 'w') as f: 
            f.write("")
            f.flush()

    def run(self):
        packet1, packet2 = None, None
        while not self.shutdown_flag.is_set():
            try:
                t_end = time.time() + MEASURMENT_DURATION_SECONDS
                accumulator = []
                while time.time() < t_end:
                    packet_a = self.device.sock.recv(BUFF_SIZE)
                    packet_b = self.device.sock.recv(BUFF_SIZE)
                    value_l = decode_packets_to_list(*order_packets(packet_a, packet_b))
                    value_array = np.array(value_l[:1024], dtype=ARRAY_DTYPE).reshape([32,32]) * HTPA_MSG_TEMP_SCALING_TO_CELSIUS
                    value_array = value_array[HTPA_IMG_CROP_START:HTPA_IMG_CROP_END, HTPA_IMG_CROP_START:HTPA_IMG_CROP_END]
                    accumulator.append(value_array.max())
                accumulated_results = np.array(accumulator, ARRAY_DTYPE)
                averaged_value = np.median(accumulated_results)
                timestamp = time.time() 
                lt = time.localtime(timestamp)
                formatted_timestamp = "{}:{}:{}".format(lt.tm_hour, lt.tm_min, lt.tm_sec)
                with open(self.fp, 'a') as f:
                    f.write("{} {}\n".format(averaged_value, formatted_timestamp))
                    f.flush()
                time.sleep(FRAME_DELAY)
            except socket.timeout:
                raise Logger_Exit(device=self.device)


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
    def __init__(self, mac, ip, port=None):
        self.mac = mac.lower()
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
        htpaisc.utils.print_if_verbose("Connecting to {}, MAC-ID: {}...".format(self.ip, self.mac), VERBOSE)
        # Bind
        try:
            self.sock.sendto(HTPA_BIND_MSG.encode(), self.address)
            _ = self.sock.recv(BUFF_SIZE)
            # READ CALIB
            self.sock.sendto(HTPA_EEDATA_OUT_MSG.encode(), self.address)
            eeprom_l = []
            try:
                while True:
                    eedata = self.sock.recv(BUFF_SIZE)
                    eeprom_l.append(eedata)
            except socket.timeout: 
                pass
            eeprom = b"".join(eeprom_l)
            self.PTATGradient = struct.unpack('f', eeprom[0x0034:0x0038])[0]
            self.PTATOffset = struct.unpack('f', eeprom[0x0038:0x003c])[0]
            # /READ CALIB
            return True
        except socket.timeout:
            htpaisc.utils.print_if_verbose("Could not bind device {}, MAC-ID: {}...".format(self.ip, self.mac), VERBOSE)
            return False
    
    def release(self):
        try:
            self.sock.sendto(HTPA_RELEASE_MSG.encode(), self.address)
            htpaisc.utils.print_if_verbose("Released device {}, MAC-ID: {}".format(self.ip, self.mac), VERBOSE)
            return True
        except socket.timeout:
            htpaisc.utils.print_if_verbose("Could not release device {}, MAC-ID: {}".format(self.ip, self.mac), VERBOSE)
            return False

    
class Temperature_Calibrator:
    def __init__(self, device):
        self.device = device
    
    def __enter__(self):
        self.device.sock.sendto(HTPA_STREAM_MSG.encode(), self.device.address)
        return self
    
    def __exit__(self, type, value, traceback):
        pass

    def capture(self):
        try:
            packet_a = self.device.sock.recv(BUFF_SIZE)
            packet_b = self.device.sock.recv(BUFF_SIZE)
            value_l = decode_packets_to_list(*order_packets(packet_a, packet_b))
            value_array = np.array(value_l[:1024], dtype=ARRAY_DTYPE).reshape([32,32]) * HTPA_MSG_TEMP_SCALING_TO_CELSIUS
            # 
            PTAT_av = np.array(value_l[-8:]).mean()
            TA = (PTAT_av * self.device.PTATGradient + self.device.PTATOffset)*1e-1
            #
            value_array = value_array[HTPA_IMG_CROP_START:HTPA_IMG_CROP_END, HTPA_IMG_CROP_START:HTPA_IMG_CROP_END]
            return value_array
        except socket.timeout:
            raise Exception("Timed-out while waiting for a frame from {}".format(self.device.mac))

        

class Device_Manager:
    """
    HTPA32x32d device manager
    # TODO: Docs
    """
    def __init__(self, log_dir):
        if not os.path.exists(log_dir):
            os.mkdir(log_dir)
        if not os.access(log_dir, os.W_OK):
            raise Exception("Specified directory is not writeable.")
        self._broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._broadcast_socket.bind(('', 0))
        self._broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._device_info_l = []
        self._connected_devices = []
        self._temperature_loggers = []

    def _add_device_info(self, info):
        """
        # XXX
        Parameters
        ----------
        info : dictionary
            Info about an HTPA32x32d device: ip, mac, port, etc.
            Use lower-case in key-words.
        """
        if info not in self._device_info_l:
            self._device_info_l.append(info)

    def scan(self, bcast_addr='<broadcast>',  duration = 1., timeout = 0.1):
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
        htpaisc.utils.print_if_verbose("Scanning network...", VERBOSE)
        self._broadcast_socket.sendto(HTPA_CALLING_MSG.encode(), (bcast_addr, HTPA_PORT))

        if not validateIP(bcast_addr):
            raise ValueError("Specified broadcasting address ({}) is incorrect.".format(bcast_addr))
        
        d_discovered = False
        iteration = 0
        while iteration < duration / timeout:
            ready = select.select([self._broadcast_socket], [], [], timeout)
            if ready[0]:
                data, addr = self._broadcast_socket.recvfrom(BUFF_SIZE)
                if HTPA32x32d_IDENT_MSG_CHUNK in data.decode():
                    mac = str(data).split("MAC-ID: ")[1].split(" ")[0]
                    htpaisc.utils.print_if_verbose("HTPA32x32d device discovered at {}, MAC-ID: {}".format(addr[0], mac), VERBOSE)
                    self._add_device_info({"mac" : mac, "ip" : addr[0], "port" : addr[1]})
                    d_discovered = True
            iteration += 1
        if d_discovered:
            return True
        else:
            htpaisc.utils.print_if_verbose("No devices discovered", VERBOSE)
    
    def _add_connected_device(self, device_obj):
        if device_obj not in self._connected_devices:
            self._connected_devices.append(device_obj)
            htpaisc.utils.print_if_verbose("Added a succsesfuly connected device {}, MAC-ID: {}".format(device_obj.ip, device_obj.mac), VERBOSE)

    def connect_all_devices(self):
        """
        Connects to all devices discovered when scanning.
        # TODO
        """
        if not len(self._device_info_l):
            raise ValueError("No devices added to the manager. Discover devices by calling 'scan' method.")
        for info in self._device_info_l:
            d = Device(**info)
            if d.connect():
                self._add_connected_device(d)
    
    def release_all_devices(self):
        """
        Releases binded HTPA32x32d devices. 
        # TODO
        """
        for d in self._connected_devices.copy():
            d.release()
            self._connected_devices.remove(d)
    '''
    def caputre_voltage_frames(self):
        """
        Capture voltage frames from all connected devices.
        Returns
        -------
        list
            List of voltage frames. 
        """
        result = {}
        for d in self._connected_devices:
            frame = d.capture_voltage_frame()
            if frame:
                result[d.mac]=frame
        return result'''

    
    def _add_temperature_logger(self, tl_obj):
        if tl_obj not in self._temperature_loggers:
            self._temperature_loggers.append(tl_obj)

    def log_all_devices(self, log_dir):
        """
        # XXX return what?
        """
        for d in self._connected_devices:
            tl = Temperature_Logger(d, log_dir)
            tl.start()
            self._add_temperature_logger(tl)

    def shutdown_all_loggers(self):
        for tl in self._temperature_loggers:
            tl.shutdown_flag.set()
        for tl in self._temperature_loggers:
            tl.join()

    def get_device_by_mac(self, mac):
        """
        # TODO 
        """
        for d in self._connected_devices:
            if d.mac == mac.lower():
                return d
        htpaisc.utils.print_if_verbose("Device with MAC-ID {} not connected".format(mac))
        return None

30.369999