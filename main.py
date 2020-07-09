import argparse
import os
import htpaisc

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='HTPA for ISelfCheck')
    parser.add_argument('log_dir', nargs='?', default="logs")
    parser.add_argument('--verbose', '-v', dest='verbose', action="store_true")
    parser.add_argument('--display', '-d', dest='display', action="store_true")
    args = parser.parse_args()

    if args.display:
        raise NotImplementedError("Not implemented yet")
    
    device_manager = htpaisc.communication.Device_Manager(args.log_dir, bcast_addr="140.123.112.255", verbose=args.verbose)
    device_manager.scan()
    device_manager.connect()

    frames = device_manager.caputre_voltage_frames()
    if len(frames):
        import pickle
        with open("frames.pkl", "wb") as f:
            pickle.dump(frames, f)
    device_manager.release()