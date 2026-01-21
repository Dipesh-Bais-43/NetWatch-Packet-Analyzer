import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import csv

class NetWatchFinal:
    def __init__(self, root):
        self.root = root
        self.root.title("NetWatch Pro - Traffic Analyzer")
        self.root.geometry("850x650")
        self.sniffing = False
        self.packet_count = 0
        self.captured_data = [] # Data store karne ke liye list

        # --- UI Design ---
        tk.Label(root, text="Network Traffic Analyzer", font=("Arial", 18, "bold")).pack(pady=10)

        # Filter Frame
        filter_frame = tk.Frame(root)
        filter_frame.pack(pady=5)
        
        tk.Label(filter_frame, text="Select Protocol: ").grid(row=0, column=0, padx=5)
        self.protocol_var = tk.StringVar(value="ALL")
        self.filter_menu = ttk.Combobox(filter_frame, textvariable=self.protocol_var, state="readonly")
        self.filter_menu['values'] = ("ALL", "TCP", "UDP", "ICMP")
        self.filter_menu.grid(row=0, column=1, padx=5)

        # Text Area
        self.text_area = scrolledtext.ScrolledText(root, width=100, height=20, state='disabled', bg="#1e1e1e", fg="#00ff00")
        self.text_area.pack(pady=10, padx=10)

        # Stats
        self.stats_label = tk.Label(root, text="Total Packets: 0", font=("Arial", 10, "italic"))
        self.stats_label.pack()

        # Buttons Frame
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=10)

        self.start_btn = tk.Button(btn_frame, text="▶ Start", command=self.start_thread, bg="green", fg="white", width=12)
        self.start_btn.grid(row=0, column=0, padx=5)

        self.stop_btn = tk.Button(btn_frame, text="■ Stop", command=self.stop_sniffing, bg="red", fg="white", width=12, state='disabled')
        self.stop_btn.grid(row=0, column=1, padx=5)

        self.export_btn = tk.Button(btn_frame, text="📥 Export CSV", command=self.export_to_csv, bg="#2c3e50", fg="white", width=12)
        self.export_btn.grid(row=0, column=2, padx=5)

        tk.Button(btn_frame, text="Clear Logs", command=self.clear_logs, width=12).grid(row=0, column=3, padx=5)

    def log_packet(self, packet):
        if packet.haslayer(IP):
            self.packet_count += 1
            src = packet[IP].src
            dst = packet[IP].dst
            proto_name = "Other"
            info = "No Extra Info"
            
            if packet.haslayer(TCP):
                proto_name = "TCP"
                info = f"Port: {packet[TCP].sport} -> {packet[TCP].dport}"
            elif packet.haslayer(UDP):
                proto_name = "UDP"
                info = f"Port: {packet[UDP].sport} -> {packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                proto_name = "ICMP"

            # List mein data save karein (CSV ke liye)
            self.captured_data.append([self.packet_count, proto_name, src, dst, info])

            # GUI Log
            log_entry = f"[{self.packet_count}] {proto_name}: {src} --> {dst} | {info}\n"
            self.text_area.configure(state='normal')
            self.text_area.insert(tk.END, log_entry)
            self.text_area.see(tk.END)
            self.text_area.configure(state='disabled')
            self.stats_label.config(text=f"Total Packets: {self.packet_count}")

    def export_to_csv(self):
        if not self.captured_data:
            messagebox.showwarning("Warning", "Export karne ke liye koi data nahi hai!")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        
        if file_path:
            try:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["ID", "Protocol", "Source IP", "Destination IP", "Info"]) # Header
                    writer.writerows(self.captured_data)
                messagebox.showinfo("Success", f"Data successfully saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"File save nahi ho saki: {e}")

    def sniffer_logic(self):
        selected = self.protocol_var.get().lower()
        bpf_filter = "" if selected == "all" else selected
        sniff(filter=bpf_filter, prn=self.log_packet, stop_filter=lambda x: not self.sniffing)

    def start_thread(self):
        self.sniffing = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.thread = threading.Thread(target=self.sniffer_logic, daemon=True)
        self.thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')

    def clear_logs(self):
        self.packet_count = 0
        self.captured_data = []
        self.stats_label.config(text="Total Packets: 0")
        self.text_area.configure(state='normal')
        self.text_area.delete('1.0', tk.END)
        self.text_area.configure(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = NetWatchFinal(root)
    root.mainloop()