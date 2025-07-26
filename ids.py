import argparse
from scapy.all import sniff, rdpcap
from detector import packet_handler
from database import init_db
from pcap_monitor import monitor_directory
from train_model import train_model
import threading
import time

def live_mode(interface=None):
    print("🚨 啟動即時監控模式...")
    sniff(prn=packet_handler, store=False, iface=interface)

def pcap_mode(file_path):
    print(f"📦 載入 PCAP 分析: {file_path}")
    packets = rdpcap(file_path)
    for pkt in packets:
        packet_handler(pkt)

if __name__ == "__main__":
    from dashboard import start_web  # 匯入 Web Dashboard

    parser = argparse.ArgumentParser(description="智能混合型網路入侵偵測系統")
    parser.add_argument("--mode", choices=["live", "pcap", "monitor"], required=True, help="執行模式")
    parser.add_argument("--file", help="PCAP 檔案路徑（僅限 pcap 模式）")
    parser.add_argument("--interface", help="指定監控的網卡")
    parser.add_argument("--web", action="store_true", help="啟動 Web 儀表板")
    parser.add_argument("--retrain-interval", type=int, help="自動重新訓練模型的時間間隔 (秒)")

    args = parser.parse_args()
    init_db()

    def retrain_loop(interval):
        while True:
            print(f"等待 {interval} 秒後重新訓練模型...")
            time.sleep(interval)
            print("開始自動重新訓練模型...")
            train_model()
            print("自動重新訓練模型完成。")

    if args.retrain_interval:
        retrain_thread = threading.Thread(target=retrain_loop, args=(args.retrain_interval,))
        retrain_thread.daemon = True  # Allow the main program to exit even if the thread is running
        retrain_thread.start()

    if args.web:
        start_web()

    if args.mode == "live":
        live_mode(interface=args.interface)
    elif args.mode == "pcap":
        if not args.file:
            print("❗ 請指定 --file 路徑")
        else:
            pcap_mode(args.file)
    elif args.mode == "monitor":
        monitor_directory()
