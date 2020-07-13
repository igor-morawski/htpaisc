import argparse
import os
import htpaisc
import time
import signal
import cv2
import numpy as np

DEBUG = True

# XXX missing frames?


def logging(args):
    device_manager = htpaisc.communication.Device_Manager(args.log_dir)
    if device_manager.scan(bcast_addr="140.123.112.255"):
        device_manager.connect_all_devices()
        device_manager.log_all_devices(args.log_dir)
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        device_manager.shutdown_all_loggers()
        device_manager.release_all_devices()
        return True
    else:
        raise Exception("No devices found while scanning")
        
def calibration(args):
    device_manager = htpaisc.communication.Device_Manager(args.log_dir)
    if device_manager.scan(bcast_addr="140.123.112.255"):
        device_manager.connect_all_devices()
        device = device_manager.get_device_by_mac(args.mac)
        with htpaisc.communication.Temperature_Calibrator(device) as tc:
            try:
                while True:
                    frame = tc.capture()
                    img = (255*(frame-frame.min())/(frame.max()-frame.min())).astype(np.uint8)
                    print(frame.max())
                    cv2.imshow("Frame", img)
                    if cv2.waitKey(50) & 0xFF == ord('q'):
                        break
            except KeyboardInterrupt:
                pass
        device_manager.release_all_devices()
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='HTPA for ISelfCheck')
    parser.add_argument('--log', '-l', dest='log', action="store_true")
    parser.add_argument('--log_dir', dest='log_dir', default="logs")
    parser.add_argument('--verbose', '-v', dest='verbose', action="store_true")
    parser.add_argument('--calibrate', '-c', dest='calibrate', action="store_true")
    parser.add_argument('--mac', dest='mac', default=None)
    parser.add_argument('--calib_dir', dest='calib_dir', default="calib")
    args = parser.parse_args()
    
    htpaisc.communication.VERBOSE = args.verbose
    
    if args.calibrate:
        calibration(args)
    elif args.log:
        logging(args)
    
