import argparse
import os
import htpaisc
import time
import signal
import cv2
import numpy as np

SCALE=10

def stream(args):
    device_manager = htpaisc.communication.Device_Manager(args.log_dir)
    if device_manager.scan(bcast_addr=args.bcast_addr): #  "140.123.112.255" for me
        device_manager.connect_all_devices()
        if args.mac:
            device = device_manager.get_device_by_mac(args.mac)
        else:
            device = device_manager._connected_devices[0]
        try:
            with htpaisc.communication.Capture(device) as cap:
                    while True:
                        frame = cap.capture()
                        temp_max = frame.max()
                        img = (255*(frame-frame.min())/(frame.max()-frame.min())).astype(np.uint8) #min-max normalization
                        # remember, cv2 size is (width, height) - opposite to np (height, width)
                        img = cv2.resize(img, dsize=(SCALE*img.shape[1], SCALE*img.shape[0])) #bicubic; NN can be used for preserving pixel edged
                        # more cm https://docs.opencv.org/2.4/modules/contrib/doc/facerec/colormaps.html
                        # remember, cv2 color tuple is BGR, other libs use RGB
                        # if you notice that your colours are opposite reverse the color channel array[:, :, ::-1]
                        img = cv2.applyColorMap(img, cv2.COLORMAP_HOT)
                        pad = 50
                        img = np.vstack([img, np.zeros([pad, img.shape[1], 3], dtype=img.dtype)])
                        text_dict = {"org":(0, img.shape[0]-20), "fontFace":cv2.FONT_HERSHEY_SIMPLEX, 
                                        "fontScale" : 0.8, "thickness" : 2, "color":(255, 255, 255)}
                        cv2.putText(img, 'MAX: {:.1f} degC'.format(temp_max), **text_dict) 
                        cv2.imshow("Frame", img)
                        if cv2.waitKey(50) & 0xFF == ord('q'):
                            break
        except KeyboardInterrupt:
            pass
        device_manager.release_all_devices()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='HTPA for ISelfCheck')
    parser.add_argument('--mac', dest='mac', default=None)
    parser.add_argument('--bcast_addr', dest='bcast_addr', default='<broadcast>')
    parser.add_argument('--log_dir', dest='log_dir', default="logs")
    parser.add_argument('--verbose', '-v', dest='verbose', action="store_true")
    args = parser.parse_args()
    htpaisc.communication.VERBOSE = args.verbose

    print("Streams HTPA32x32d specified by --mac. If not --mac, the first HTPA32x32d found is streamed.")
    print("Quit stream by pressing 'q'")
    stream(args)