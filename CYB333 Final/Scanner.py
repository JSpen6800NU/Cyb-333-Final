import nmap  # For network scanning
import requests  # For analyzing web application vulnerabilities
import json  # For handling report generation
import socket  # For host information retrieval
import tkinter as tk  # For GUI
from tkinter import filedialog  # For file dialog
import os  # For handling file paths

# Initialize the Nmap scanner
nm = nmap.PortScanner()


# Function for host reconnaissance
def host_recon(target):
    try:
        print(f"[INFO] Resolving host for {target}...")
        ip_address = socket.gethostbyname(target)
        hostname = socket.gethostbyaddr(ip_address)[0]
        print(f"[INFO] Host: {hostname}, IP: {ip_address}")
        return {"hostname": hostname, "ip_address": ip_address}
    except Exception as e:
        print(f"[ERROR] Host reconnaissance failed for {target}: {e}")
        return None


# Function for port scanning
def port_scan(target, ports="1-1024"):
    try:
        print(f"[INFO] Scanning ports on {target}...")
        nm.scan(hosts=target, arguments=f"-p {ports} --open")
        open_ports = []
        for proto in nm[target].all_protocols():
            ports = nm[target][proto].keys()
            open_ports.extend(ports)
        print(f"[INFO] Open ports found: {open_ports}")
        return open_ports
    except Exception as e:
        print(f"[ERROR] Port scanning failed for {target}: {e}")
        return []


# Function to check web application vulnerabilities
def check_web_vulnerabilities(target_url):
    print(f"[INFO] Checking web vulnerabilities for {target_url}...")
    vulnerabilities = []
    try:
        response = requests.options(target_url)
        if response.status_code == 200 and 'OPTIONS' in response.headers.get('Allow', ''):
            vulnerabilities.append("HTTP OPTIONS method enabled - may expose sensitive information.")

        for file in ["robots.txt", ".env", "admin.php"]:
            resp = requests.get(f"{target_url}/{file}")
            if resp.status_code == 200:
                vulnerabilities.append(f"Sensitive file found: {file}")
    except Exception as e:
        print(f"[ERROR] Web vulnerability check failed for {target_url}: {e}")
    return vulnerabilities


# Function to generate a report
def generate_report(data, filename="scan_report.json"):
    try:
        with open(filename, 'w') as report_file:
            json.dump(data, report_file, indent=4)
        print(f"[INFO] Report saved as {filename}")
    except Exception as e:
        print(f"[ERROR] Report generation failed: {e}")


# Function to handle multiple targets
def scan_multiple_targets(targets, save_path):
    all_results = {}

    for target in targets:
        target_info = {}
        print(f"[INFO] Starting scan for {target}")

        host_info = host_recon(target)
        if not host_info:
            print(f"[ERROR] Host reconnaissance failed for {target}. Skipping.")
            continue
        target_info["host_info"] = host_info

        open_ports = port_scan(host_info['ip_address'])
        target_info["open_ports"] = open_ports

        web_vulns = check_web_vulnerabilities(target)
        target_info["web_vulnerabilities"] = web_vulns

        all_results[target] = target_info

    generate_report(all_results, save_path)


# Main function to integrate all functionalities
def main():
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    # Get the file save location from the user using a file dialog
    save_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if not save_path:
        print("[ERROR] No save path selected. Exiting.")
        return

    # Create a new top-level window for entering the target list
    input_window = tk.Toplevel()
    input_window.title("Enter Targets")

    # Label and text field for the user to input targets
    tk.Label(input_window, text="Enter a list of target domains or IPs (comma-separated):").pack(padx=10, pady=5)
    targets_entry = tk.Entry(input_window, width=50)
    targets_entry.pack(padx=10, pady=5)

    # Function to handle the start button click
    def on_start_button_click():
        try:
            targets_input = targets_entry.get().strip()
            targets = [target.strip() for target in targets_input.split(",")]

            if not targets:
                print("[ERROR] No targets provided. Exiting.")
                input_window.destroy()
                return

            print(f"[INFO] Targets: {targets}")
            scan_multiple_targets(targets, save_path)
        except Exception as e:
            print(f"[ERROR] Error during scan process: {e}")
        finally:
            input_window.destroy()

    # Add a Start button to trigger the scan
    start_button = tk.Button(input_window, text="Start Scan", command=on_start_button_click)
    start_button.pack(padx=10, pady=20)

    # Run the Tkinter event loop
    input_window.mainloop()


if __name__ == "__main__":
    main()
