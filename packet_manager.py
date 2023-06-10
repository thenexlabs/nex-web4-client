import psutil, GPUtil, requests
from scapy.all import *
import datetime

class PacketManager:

  def __init__(self, apiKey, printGUI, apiResponseMessage):
    self.apiKey = apiKey
    self.printGUI = printGUI
    self.apiResponseMessage = apiResponseMessage
    self.packetsBuffer = []

  def updateApiResponseMessage(self, newApiResponseMessage):
    global apiResponseMessage
    apiResponseMessage = newApiResponseMessage
    self.apiResponseMessage = newApiResponseMessage

  def updateApiKey(self, newApiKey):
    global apiKey
    apiKey = newApiKey
    self.apiKey = newApiKey

  # sniff callback
  def packet_callback(self, packet):
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
      src_port = 0
      dst_port = 0
      duration = packet[protocol_type].time - packet.time
      service = "private"
      flag = 'SF'
      src_bytes = 0
      dst_bytes = 0
      land = 1 if src_ip == dst_ip else 0
      wrong_fragment = 0
      # Check if the protocol has the urgptr attribute 'urgent'
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
        wrong_fragment = packet[protocol_type].flags if 'flags' in packet[protocol_type].fields and packet[protocol_type].flags & 0x1 else None
        hot = packet[protocol_type].options if 'options' in packet[protocol_type].fields and packet[protocol_type].options == [('MSS', 536), ('NOP', ()), ('WScale', 10), ('NOP', ()), ('Timestamp', (3547056421, 0))] else None
        root_shell = packet[protocol_type].flags if 'flags' in packet[protocol_type].fields and packet[protocol_type].flags & 0x4000 else None
        su_attempts = packet[protocol_type].options if 'options' in packet[protocol_type].fields and packet[protocol_type].options == [('MSS', 536), ('NOP', ()), ('WScale', 10), ('NOP', ()), ('Timestamp', (3547056421, 0))] else None
        num_root = packet[protocol_type].options if 'options' in packet[protocol_type].fields and packet[protocol_type].options == [('MSS', 536), ('NOP', ()), ('WScale', 10), ('NOP', ()), ('Timestamp', (3547056421, 0))] else None
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

      # Extract service
      # Check if the packet has a TCP or UDP layer
      if packet.haslayer(TCP) or packet.haslayer(UDP):
        # Get the source and destination ports
        src_port = packet.sport
        dst_port = packet.dport

        # Determine the service based on the port number
        if src_port == 80 or dst_port == 80:
            service = 'http'
        elif src_port == 22 or dst_port == 22:
            service = 'ssh'
        elif src_port == 1234 or dst_port == 1234:
            service = 'private_1234'
        elif src_port == 5678 or dst_port == 5678:
            service = 'domain_u'
        else:
            service = 'private'

      # Extract src bytes and dst_bytes
      # Check if the packet has an IP layer
      if packet.haslayer(IP):
        # Get the IP layer
        ip_layer = packet[IP]

        # Get the source and destination IP addresses
        src_bytes = len(ip_layer)
        dst_bytes = len(ip_layer.payload)

        # Get the packet length
        packet_length = ip_layer.len

      # track CPU usage
      cpu_usage = psutil.cpu_percent()

      # track GPU usage
      gpus = GPUtil.getGPUs()
      gpu_data = {}

      now = datetime.datetime.now()
      data = {
        "cpu_usage": cpu_usage,
        "timestamp": int(now.timestamp()),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "duration": duration,
        "protocol_type": protocol_type,
        "service": service,
        #"flag": flag,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        #"land": land,
        # "wrong_fragment": wrong_fragment,
        #"urgent": urgent,
        # "hot": hot,
        # "num_failed_logins": num_failed_logins,
        # "logged_in": logged_in,
        # "num_compromised": num_compromised,
        # "root_shell": root_shell,
        # "su_attempted": su_attempted,
        # "num_root": num_root,
        # "num_file_creations": num_file_creations,
        # "num_shells": num_shells,
        # "num_access_files": num_access_files,
        # "num_outbound_cmds": num_outbound_cmds,
        # "is_host_login": is_host_login,
        # "is_guest_login": is_guest_login,
        # "count": count,
        # "srv_count": srv_count,
        # "serror_rate": serror_rate,
        # "srv_serror_rate": srv_serror_rate,
        # "rerror_rate": rerror_rate,
        # "srv_rerror_rate": srv_rerror_rate,
        # "same_srv_rate": same_srv_rate,
        # "diff_srv_rate": diff_srv_rate,
        # "srv_diff_host_rate": srv_diff_host_rate,
        # "dst_host_count": dst_host_count,
        # "dst_host_srv_count": dst_host_srv_count,
        # "dst_host_same_srv_rate": dst_host_same_srv_rate,
        # "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
        # "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
        # "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
        # "dst_host_serror_rate": dst_host_serror_rate,
        # "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
        # "dst_host_rerror_rate": dst_host_rerror_rate,
        # "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate
      }
      for i, gpu in enumerate(gpus):
        gpu_usage = gpu.load
        data[f"gpu_{i+1}_usage"] = gpu_usage
      
      self.printGUI('-----------------------------------------')
      self.printGUI(len(self.packetsBuffer))

      self.packetsBuffer.append(data)

      numPacketsUntilAddedToDB = 300

      if( len(self.packetsBuffer) >= numPacketsUntilAddedToDB ):
        # Send the collected information to the API endpoint
        api_url = "https://api.thenex.world/network-monitor-data"
        headers = {
          'nex-api-key': self.apiKey,
          'Content-type': 'application/json'
        }

        json = {
          'packets': self.packetsBuffer
        }

        response = requests.post(
          api_url, 
          headers=headers, 
          json=json
        )
        responseJson = response.json()
      
        self.printGUI(responseJson)
        #self.printGUI(response.status_code)

        if(responseJson['message']):
          self.updateApiResponseMessage(responseJson['message'])
          # if('Data inserted successfully' == responseJson['message']):
          #   self.packetsBuffer = []

        self.packetsBuffer = []
      # self.printGUI(self.packetsBuffer[len(self.packetsBuffer)-1])

    except Exception as e:
      self.printGUI(e)
      self.packetsBuffer = []