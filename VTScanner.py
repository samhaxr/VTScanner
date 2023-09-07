#!Coded by Suleman Malik
#!www.sulemanmalik.com
#!Twitter: @sulemanmalik_3
#!Linkedin: http://linkedin.com/in/sulemanmalik03/
#
# Copyright (c) 2023 Suleman Malik
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import requests
import time
import hashlib
import webbrowser
import threading
import configparser
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from tkinter import ttk
from queue import Queue
from jinja2 import Template

class VirusTotalScannerGUI:
    def __init__(self, root):
        self.root = root
        self.check_and_run()
        self.root.title("VT Scanner v1.0")
        self.root.geometry("900x680") 
        self.root.resizable(False, False)
        self.should_stop = False
        self.banner_photo = tk.PhotoImage(file="VTS.ppm")
        new_height = self.banner_photo.height() // 130  
        self.banner_photo = self.banner_photo.subsample(1, new_height)
        self.banner_label = tk.Label(root, image=self.banner_photo, anchor="w")
        self.banner_label.pack()
        api_wait_frame = tk.Frame(root)
        api_wait_frame.pack(side=tk.TOP, padx=20, pady=10, anchor="w")
        self.api_label = tk.Label(api_wait_frame, text="API Key:", font=("Helvetica", 10))
        self.api_label.pack(side=tk.LEFT, padx=10)
        self.api_entry = tk.Entry(api_wait_frame, font=("Helvetica", 10))
        self.api_entry.pack(side=tk.LEFT, padx=10)
        self.api_button = tk.Button(api_wait_frame, text="Save API", command=self.toggle_api_key, font=("Helvetica", 10))
        self.api_button.pack(side=tk.LEFT, padx=10)
        self.wait_time_label = tk.Label(api_wait_frame, text="Delay(sec):", font=("Helvetica", 10))
        self.wait_time_label.pack(side=tk.LEFT, padx=10)
        self.wait_time_entry = tk.Entry(api_wait_frame, font=("Helvetica", 10))
        self.wait_time_entry.insert(0, "20")  
        self.wait_time_entry.pack(side=tk.LEFT, padx=10)
        button_frame = tk.Frame(root)
        button_frame.pack(pady=20, padx=20, anchor="w")  
        self.browse_button = tk.Button(button_frame, text="Browse", command=self.browse_directory, font=("Helvetica", 10))
        self.browse_button.pack(pady=10, padx=10, side=tk.LEFT)
        self.start_scan_button = tk.Button(button_frame, text="Start Scan", command=self.start_scan, font=("Helvetica", 10), bg="green", fg="white")
        self.start_scan_button.pack(pady=10, padx=10, side=tk.LEFT)
        self.stop_scan_button = tk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED, font=("Helvetica", 10), bg="red", fg="white")
        self.stop_scan_button.pack(pady=10, padx=10, side=tk.LEFT)
        self.print_report_button = tk.Button(button_frame, text="Print Report", command=self.generate_report, font=("Helvetica", 10))
        self.print_report_button.pack(pady=10, padx=10, side=tk.LEFT)
        self.print_report_button.config(state=tk.DISABLED)
        author_frame = tk.Frame(root)
        author_frame.pack(side=tk.BOTTOM, padx=20, pady=10, anchor="se")  
        author_label = tk.Label(author_frame, text="Dev: Suleman Malik\n www.sulemanmalik.com", font=("Helvetica", 10))
        author_label.pack()
        self.result_tree = ttk.Treeview(root, columns=("Number", "Name", "Size", "Detection", "Location"), show="headings")
        self.result_tree.heading("Number", text="#")
        self.result_tree.heading("Name", text="Name")
        self.result_tree.heading("Size", text="Size")
        self.result_tree.heading("Detection", text="Detection")
        self.result_tree.heading("Location", text="Location")
        self.result_tree.column("Number", anchor="center", width=60)
        self.result_tree.column("Name", width=200)
        self.result_tree.column("Size", anchor="center", width=120)
        self.result_tree.column("Detection", anchor="center", width=180)
        self.result_tree.column("Location", anchor="center", width=360)
        self.result_tree.pack(pady=20, expand=True, fill='both')
        self.result_tree.bind("<Double-1>", self.open_url)
        self.current_file_label = tk.Label(root, text="", font=("Helvetica", 10, "bold"))
        self.current_file_label.pack(pady=10)
        self.api_key = ""
        self.directory_path = ""
        self.scan_queue = Queue()
        self.scan_thread = None
        self.config = configparser.ConfigParser()
        self.config.read("config.ini")
        if "API" in self.config:
            self.api_key = self.config["API"].get("key", "")
            if self.api_key:
                self.api_entry.delete(0, tk.END)
                self.api_entry.insert(0, self.api_key)
                self.api_button.config(text="Remove API")
                self.browse_button.config(state=tk.NORMAL)
        self.browse_button.config(state=tk.DISABLED) 
        self.start_scan_button.config(state=tk.DISABLED) 
        self.stop_scan_button.config(state=tk.DISABLED) 
        if self.api_key: 
            self.browse_button.config(state=tk.NORMAL)
        self.root.update()

    def check_and_run(self):
        if os.path.exists("VTS.ppm"):
            try:
                self.banner_photo = tk.PhotoImage(file="VTS.ppm")
            except tk.TclError:
                tk.messagebox.showerror("Error", "Invalid file 'VTS.ppm'")
                self.root.quit()  
                sys.exit(1)
        else:
            tk.messagebox.showerror("Error", "File 'VTS.ppm' not found")
            sys.exit(1)
            self.root.quit()  
        new_height = self.banner_photo.height() // 2  
        self.banner_photo = self.banner_photo.subsample(1, new_height)
        self.banner_label = tk.Label(root, image=self.banner_photo, anchor="ne")
        self.banner_label.pack()

    def generate_report(self):
        scan_results = []  
        items = self.result_tree.get_children()
        if not items:
            tk.messagebox.showinfo("Info", "No scan results to generate a report.")
            return
        for item in items:
            values = self.result_tree.item(item, "values")
            permalink = self.result_tree.item(item, "tags")[0]
            scan_results.append({
                'number': values[0],
                'name': values[1],
                'size': values[2],
                'detection': values[3],
                'location': values[4],
                'permalink': permalink
            })
        report_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Scan Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                }
                table {
                    border-collapse: collapse;
                    width: 100%;
                }
                th, td {
                    border: 1px solid #dddddd;
                    text-align: left;
                    padding: 8px;
                }
                th {
                    background-color: #f2f2f2;
                }
            </style>
        </head>
        <body>
            <h1>Scan Report</h1>
            <table>
                <tr>
                    <th>#</th>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Detection</th>
                    <th>Location</th>
                    <th>Permalink</th>
                </tr>
                {% for result in scan_results %}
                <tr>
                    <td>{{ result.number }}</td>
                    <td>{{ result.name }}</td>
                    <td>{{ result.size }}</td>
                    <td>{{ result.detection }}</td>
                    <td>{{ result.location }}</td>
                    <td><a href="{{ result.permalink }}" target="_blank">Link</a></td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """
        template = Template(report_template)
        rendered_report = template.render(scan_results=scan_results)
        with open("scan_report.html", "w") as report_file:
            report_file.write(rendered_report)
        tk.messagebox.showinfo("Info", "Scan report generated as scan_report.html.")
        
    def toggle_api_key(self):
        if self.api_key:
            self.api_entry.delete(0, tk.END)
            self.api_key = ""
            self.api_button.config(text="Save Key")
            self.browse_button.config(state=tk.DISABLED)
            self.start_scan_button.config(state=tk.DISABLED)
            if "API" in self.config:
                del self.config["API"]["key"]
                with open("config.ini", "w") as configfile:
                    self.config.write(configfile)
        else:
            api_key = self.api_entry.get().strip()
            if api_key:
                self.api_key = api_key
                self.api_button.config(text="Remove Key")
                self.browse_button.config(state=tk.NORMAL)
                if "API" not in self.config:
                    self.config["API"] = {}
                self.config["API"]["key"] = self.api_key
                with open("config.ini", "w") as configfile:
                    self.config.write(configfile)
            else:
                tk.messagebox.showerror("Error", "API key cannot be empty")

    def insert_result(self, number, name, size, detection, location, permalink):
        self.result_tree.insert("", "end", values=(number, name, size, detection, location, permalink), tags=(permalink,))

    def open_url(self, event):
        item = self.result_tree.selection()
        if item:
            tags = self.result_tree.item(item, "tags")
            if tags:
                permalink = tags[0]
                if permalink != '-':
                    try:
                        webbrowser.open_new(permalink)
                    except Exception:
                        pass

    def browse_directory(self):
        self.directory_path = filedialog.askdirectory()
        if self.directory_path:
            self.start_scan_button.config(state=tk.NORMAL)  

    def upload_to_virustotal(self, file_path, hash_value=None):
        if not self.api_key:
            tk.messagebox.showerror("Error", "Missing API key")
            return
        wait_time = int(self.wait_time_entry.get())
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': self.api_key}
        if hash_value:
            params['resource'] = hash_value
        else:
            files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
            response = requests.post(url, files=files, params=params)
            scan_id = response.json()['scan_id']
            while True:
                report_params = {'apikey': self.api_key, 'resource': scan_id}
                report_response = requests.get(report_url, params=report_params)
                report_data = report_response.json()
                if report_data['response_code'] == 1:  
                    return report_data
                elif report_data['response_code'] == -2:  
                    time.sleep(wait_time)  
                else:
                    return None  

    def save_api_key(self):
        api_key = self.api_entry.get().strip()
        if api_key:
            self.api_key = api_key
            self.save_api_button.config(state=tk.DISABLED)
            self.browse_button.config(state=tk.NORMAL)
            if "API" not in self.config:
                self.config["API"] = {}
            self.config["API"]["key"] = self.api_key
            with open("config.ini", "w") as configfile:
                self.config.write(configfile)
        else:
            tk.messagebox.showerror("Error", "API key cannot be empty")

    def format_size(self, size_bytes):
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0

    def start_scan(self):
        self.result_tree.delete(*self.result_tree.get_children())
        self.scan_queue.queue.clear()
        for root_dir, _, files in os.walk(self.directory_path):
            for file in files:
                self.scan_queue.put(os.path.join(root_dir, file))
        if not self.scan_thread or not self.scan_thread.is_alive():
            self.scan_thread = threading.Thread(target=self.scan_files)
            self.scan_thread.start()
            self.start_scan_button.config(state=tk.DISABLED)  
            self.stop_scan_button.config(state=tk.NORMAL)
            self.root.update()

    def stop_scan(self):
        self.should_stop = True
        self.stop_scan_button.config(state=tk.DISABLED)
        self.print_report_button.config(state=tk.NORMAL)  

    def update_label(self, file_path):
        self.current_file_label.config(text=f"Scanning: {os.path.basename(file_path)}")
        self.root.update()

    def scan_files(self):
        wait_time = int(self.wait_time_entry.get())
        files_to_rescan = list(self.scan_queue.queue)
        scan_number = 1
        while files_to_rescan and not self.should_stop:
            if self.should_stop:
                self.current_file_label.config(text="Scanning stopped")
                self.update_label(text="Scanning stopped")
                break
            if not self.scan_queue.empty():
                file_path = files_to_rescan.pop(0)
                self.update_label(file_path)
                hash_value = self.calculate_hash(file_path)
                try:
                    report_response = self.get_scan_report(hash_value)
                    time.sleep(wait_time)
                    if report_response is not None and "positives" in report_response:
                        detection = f"{report_response['positives']} out of {report_response['total']} scans"
                        formatted_size = self.format_size(os.path.getsize(file_path))
                        self.insert_result(scan_number, os.path.basename(file_path), formatted_size, detection, file_path, report_response.get('permalink', '-'))
                        scan_number += 1
                    else:
                        response_json = self.upload_to_virustotal(file_path)
                        if response_json and "resource" in response_json:
                            files_to_rescan.append(file_path)
                            detection = f"{response_json['positives']} out of {response_json['total']} scans"
                            self.insert_result(scan_number, os.path.basename(file_path), self.format_size(os.path.getsize(file_path)), detection, file_path, response_json.get('permalink', '-'))
                        time.sleep(wait_time)
                        self.scan_queue.task_done()
                        scan_number += 1
                except requests.exceptions.RequestException as e:
                    tk.messagebox.showerror("Error", f"An error occurred: Invalid API key or excessive requests. Retry with correct key or increase delay time")
                    break
            else:
                break
        self.should_stop = False
        self.current_file_label.config(text="Scanning complete")
        self.stop_scan_button.config(state=tk.DISABLED)
        self.start_scan_button.config(state=tk.NORMAL)
        self.print_report_button.config(state=tk.NORMAL)

    def get_scan_report(self, resource):
        if not self.api_key:
            tk.messagebox.showerror("Error", "Missing API key")
            return
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': self.api_key, 'resource': resource}
        response = requests.get(url, params=params)
        return response.json()

    def open_url(self, event):
        item = self.result_tree.selection()
        if item:
            permalink = self.result_tree.item(item, "tags")[0]
            if permalink != '-':
                try:
                    webbrowser.open_new(permalink)
                except Exception:
                    pass

    def calculate_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

if __name__ == "__main__":
    root = tk.Tk()
    scanner = VirusTotalScannerGUI(root)
    root.mainloop()
