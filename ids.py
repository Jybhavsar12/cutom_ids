from threading import Thread
import signal
import sys
import detectors.signature_detector as signature_detector
import detectors.anomaly_detector as anomaly_detector

def run_signature_detector():
    signature_detector.start_sniffing()

def run_anomaly_detector():
    anomaly_detector.start_sniffing()

def signal_handler(sig, frame):
    print("\n[INFO] Interrupt received, stopping IDS...")
    sys.exit(0)

if __name__ == "__main__":
    print("Starting Custom IDS...")

    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    t1 = Thread(target=run_signature_detector, daemon=True)
    t2 = Thread(target=run_anomaly_detector, daemon=True)

    t1.start()
    t2.start()

    # Keep main thread alive while child threads run
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[INFO] Exiting...")

