import requests
from scapy.all import *
import sys
import datetime
from tkinter import *
from threading import Thread

# Read the api key from the command line
apiKey = sys.argv[1]

# GUI
root = Tk()
root.geometry("300x100")
root.configure(bg='black')
root.title("The NEX Web4 Client")

# Global variable to control whether the sniff function should continue running
running = True

def Close():
    global running
    # Set the 'running' flag to False to stop the sniff function
    running = False
    # Destroy the Tkinter window
    root.destroy()

exit_button = Button(root, text="Stop", command=Close)
exit_button.pack(pady=20)
exit_button.configure(bg='black', fg='lime')

def packet_callback(packet):
    # Check if packet has IP layer
    if IP in packet:
      protocol_type = "IP"
    # Check if packet has TCP layer
    elif TCP in packet:
      protocol_type = "TCP"
    # Check if packet has UDP layer
    elif UDP in packet:
      protocol_type = "UDP"
    # Check if packet has DNS layer
    elif DNS in packet:
      protocol_type = "DNS"
    # Check if packet has Ether layer
    elif Ether in packet:
      protocol_type = "Ether"
    # Otherwise, print unknown protocol type
    else:
      protocol_type = "Unknown"
    # print(packet.summary())
    # print(packet.fields)
    # print(packet[protocol_type].fields)
    try:
      # Extract required information from the packet
      src_ip = packet[protocol_type].src
      dst_ip = packet[protocol_type].dst
      src_port = packet[protocol_type].sport if protocol_type in ['TCP', 'UDP'] and 'sport' in packet[protocol_type].fields else None
      dst_port = packet[protocol_type].dport if protocol_type in ['TCP', 'UDP'] and 'dport' in packet[protocol_type].fields else None
      duration = packet.time - packet[protocol_type].time
      service = ""
      flag = packet[protocol_type].flags if protocol_type == 'TCP' and 'flags' in packet[protocol_type].fields else None
      src_bytes = len(packet[protocol_type].payload) if protocol_type in ['TCP', 'UDP'] else None
      dst_bytes = 0
      land = 0
      wrong_fragment = 0
      # Check if the protocol has the urgptr attribute
      if hasattr(packet[protocol_type], 'urgptr'):
        urgent = packet[protocol_type].urgptr
      else:
        urgent = 0
      hot = 0
      num_failed_logins = 0
      logged_in = 0
      num_compromised = 0
      root_shell = 0
      su_attempted = 0
      num_root = 0
      num_file_creations = 0
      num_shells = 0
      num_access_files = 0
      num_outbound_cmds = 0
      is_host_login = 0
      is_guest_login = 0
      count = 0
      srv_count = 0
      serror_rate = 0
      srv_serror_rate = 0
      rerror_rate = 0
      srv_rerror_rate = 0
      same_srv_rate = 0
      diff_srv_rate = 0
      srv_diff_host_rate = 0
      dst_host_count = 0
      dst_host_srv_count = 0
      dst_host_same_srv_rate = 0
      dst_host_diff_srv_rate = 0
      dst_host_same_src_port_rate = 0
      dst_host_srv_diff_host_rate = 0
      dst_host_serror_rate = 0
      dst_host_srv_serror_rate = 0
      dst_host_rerror_rate = 0
      dst_host_srv_rerror_rate = 0

      # Extract required information from the packet
      if protocol_type == "TCP":
        dst_bytes = packet[protocol_type].dlen if 'dlen' in packet[protocol_type].fields else None
        land = packet[protocol_type].options if 'options' in packet[protocol_type].fields and packet[protocol_type].options == [('MSS', 536), ('WScale', 10), ('NOP', ()), ('NOP', ()), ('Timestamp', (3547056421, 0))] else None
        wrong_fragment = packet[protocol_type].flags if 'flags' in packet[protocol_type].fields and packet[protocol_type].flags & 0x1 else None
        hot = packet[protocol_type].options if 'options' in packet[protocol_type].fields and packet[protocol_type].options == [('MSS', 536), ('NOP', ()), ('WScale', 10), ('NOP', ()), ('Timestamp', (3547056421, 0))] else None
        root_shell = packet[protocol_type].flags if 'flags' in packet[protocol_type].fields and packet[protocol_type].flags & 0x4000 else None
        su_attempts = packet[protocol_type].options if 'options' in packet[protocol_type].fields and packet[protocol_type].options == [('MSS', 536), ('NOP', ()), ('WScale', 10), ('NOP', ()), ('Timestamp', (3547056421, 0))] else None
        num_root = packet[protocol_type].options if 'options' in packet[protocol_type].fields and packet[protocol_type].options == [('MSS', 536), ('NOP', ()), ('WScale', 10), ('NOP', ()), ('Timestamp', (3547056421, 0))] else None
        dst_bytes = packet[protocol_type].dsize
        if packet[protocol_type].flags & 0x010:
            land = 1
        if packet[protocol_type].flags & 0x080:
            num_failed_logins += 1
        if packet[protocol_type].flags & 0x020:
            logged_in = 1
        if packet[protocol_type].flags & 0x008:
            num_compromised += 1
        if packet[protocol_type].flags & 0x002:
            root_shell = 1
        if packet[protocol_type].flags & 0x001:
            su_attempted = 1
        if packet[protocol_type].flags & 0x004:
            num_root += 1
        if packet[protocol_type].flags & 0x040:
            num_file_creations += 1
        src_bytes = len(packet[protocol_type].payload)
        count = 1
        srv_count = 1
        serror_rate = packet[protocol_type].sprintf("%.2f%%", packet[protocol_type].serror)
        srv_serror_rate = packet[protocol_type].sprintf("%.2f%%", packet[protocol_type].srv_serror)
        rerror_rate = packet[protocol_type].sprintf("%.2f%%", packet[protocol_type].rerror)
        srv_rerror_rate = packet[protocol_type].sprintf("%.2f%%", packet[protocol_type].srv_rerror)
        same_srv_rate = packet[protocol_type].sprintf("%.2f%%", packet[protocol_type].sprintf(packet[protocol_type].same_syn) / float(packet[protocol_type].sprintf(packet[protocol_type].count)))
        diff_srv_rate = packet[protocol_type].sprintf("%.2f%%", (1 - float(packet[protocol_type].sprintf(packet[protocol_type].same_syn)) / float(packet[protocol_type].sprintf(packet[protocol_type].count))))
        srv_diff_host_rate = packet[protocol_type].sprintf("%.2f%%", packet[protocol_type].sprintf(packet[protocol_type].diff_syn) / float(packet[protocol_type].sprintf(packet[protocol_type].srv_count)))
        dst_host_count = 1
        dst_host_srv_count = 1

      # Send the collected information to the API endpoint
      api_url = "https://api.thenex.world/.netlify/functions/network-monitor-data"
      headers = {
        'nex-api-key': apiKey,
        'Content-type': 'application/json'
      }
      now = datetime.datetime.now()
      data = {
        "timestamp": int(now.timestamp()),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "duration": duration,
        "protocol_type": protocol_type,
        "service": service,
        "flag": flag,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "land": land,
        "wrong_fragment": wrong_fragment,
        "urgent": urgent,
        "hot": hot,
        "num_failed_logins": num_failed_logins,
        "logged_in": logged_in,
        "num_compromised": num_compromised,
        "root_shell": root_shell,
        "su_attempted": su_attempted,
        "num_root": num_root,
        "num_file_creations": num_file_creations,
        "num_shells": num_shells,
        "num_access_files": num_access_files,
        "num_outbound_cmds": num_outbound_cmds,
        "is_host_login": is_host_login,
        "is_guest_login": is_guest_login,
        "count": count,
        "srv_count": srv_count,
        "serror_rate": serror_rate,
        "srv_serror_rate": srv_serror_rate,
        "rerror_rate": rerror_rate,
        "srv_rerror_rate": srv_rerror_rate,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "srv_diff_host_rate": srv_diff_host_rate,
        "dst_host_count": dst_host_count,
        "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate,
        "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
        "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
        "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
        "dst_host_serror_rate": dst_host_serror_rate,
        "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
        "dst_host_rerror_rate": dst_host_rerror_rate,
        "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate
      }
      # if(data.src_ip == 'ff:ff:ff:ff:ff:ff'){
      # }else if(data.dst_ip == 'ff:ff:ff:ff:ff:ff'){
      # }else{
      response = requests.post(api_url, headers=headers, json=data)
      print(response.status_code)
      print(response.json())
      print('-----------------------------------------')
      # }
      # print(data)
    except ExceptionType:
      print(ExceptionType)

def stop_sniff(packet):
    # Return True to stop sniffing when the 'running' flag is False
    return not running

def sniff_thread():
    # Sniff packets until the 'stop_sniff' function returns True
    sniff(prn=packet_callback, store=0, stop_filter=stop_sniff)

# Start the sniff function in a separate thread
t = Thread(target=sniff_thread)
t.start()

# Run the GUI
root.mainloop()