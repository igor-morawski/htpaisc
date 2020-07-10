import argparse
import os
import htpaisc

DEBUG = True

# XXX missing frames?


def logging(args):
    htpaisc.communication.VERBOSE = args.verbose
    device_manager = htpaisc.communication.Device_Manager(args.log_dir)
    if DEBUG:
        if device_manager.scan(bcast_addr="140.123.112.255"):
            device_manager.connect()
            frames = device_manager.caputre_voltage_frames()
            # XXX logging
            device_manager.release()
            return frames
        else:
            return None
    else:
        raise NotImplementedError

def calibration(args):
    htpaisc.communication.VERBOSE = args.verbose
    device_manager = htpaisc.communication.Device_Manager(args.log_dir)
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='HTPA for ISelfCheck')
    parser.add_argument('--log', '-l', dest='log', action="store_true")
    parser.add_argument('--log_dir', dest='log_dir', default="logs")
    parser.add_argument('--verbose', '-v', dest='verbose', action="store_true")
    parser.add_argument('--display', '-d', dest='display', action="store_true")
    parser.add_argument('--calibrate', '-c', dest='calibrate', action="store_true")
    parser.add_argument('--calib_dir', dest='calib_dir', default="calib")
    args = parser.parse_args()

    if args.display:
        raise NotImplementedError("Not implemented yet")
    
    if args.calibrate:
        calibration(args)
    elif args.log:
        logging(args)
    
