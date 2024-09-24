import tkinter as tk
from tkinter import scrolledtext
import subprocess
import socket
import threading

class PingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner Tool")
        
        # Label for instructions
        self.label = tk.Label(root, text="Enter the IP range (e.g., 142.250.77):")
        self.label.pack(pady=10)
        
        # Input for the base IP address (first 3 octets)
        self.ip_entry = tk.Entry(root, width=30)
        self.ip_entry.pack(pady=5)
        
        # Button to start the ping process
        self.ping_button = tk.Button(root, text="Start Ping", command=self.start_ping)
        self.ping_button.pack(pady=10)

        # Button to start port scan
        self.port_scan_button = tk.Button(root, text="Scan Open Ports", command=self.start_port_scan_thread)
        self.port_scan_button.pack(pady=10)

        # Text area to display results
        self.results_area = scrolledtext.ScrolledText(root, width=60, height=20)
        self.results_area.pack(pady=10)

    def start_ping(self):
        self.results_area.delete(1.0, tk.END)  # Clear previous results
        base_ip = self.ip_entry.get()
        
        if not base_ip:
            self.results_area.insert(tk.END, "Please enter a valid base IP address.\n")
            return

        # Ping the range of IPs from base_ip.1 to base_ip.10
        last_dot = base_ip.rfind('.')
        base_ip = base_ip[:last_dot]
        
        for i in range(1, 11):
            address = f"{base_ip}.{i}"
            self.results_area.insert(tk.END, f"Pinging {address}...\n")
            self.root.update()  # Update the GUI during the ping process
            
            # Call the ping command
            res = subprocess.call(['ping', '-n', '3', address])
            if res == 0:
                self.results_area.insert(tk.END, f"Ping to {address} ok\n")
            elif res == 2:
                self.results_area.insert(tk.END, f"No response from {address}\n")
            else:
                self.results_area.insert(tk.END, f"Ping to {address} failed!\n")

    def start_port_scan_thread(self):
        threading.Thread(target=self.scan_ports).start()  # Start the port scan in a new thread

    def scan_ports(self):
        self.results_area.delete(1.0, tk.END)  # Clear previous results
        base_ip = self.ip_entry.get()
        
        if not base_ip:
            self.results_area.insert(tk.END, "Please enter a valid base IP address.\n")
            return    
        ports_to_scan = range(1, 1025)  # Scanning ports from 1 to 1024
        self.results_area.insert(tk.END, f"Scanning ports on {base_ip}...\n")
        self.root.update()  # Update the GUI during the scanning process
            
        for port in ports_to_scan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Set timeout for connection attempts
                
            result = sock.connect_ex((base_ip, port))
            if result == 0:
                self.results_area.insert(tk.END, f"Port {port} is open on {base_ip}\n")
            sock.close()
        self.results_area.insert(tk.END,"Port Scan Complete")

if __name__ == "__main__":
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()
