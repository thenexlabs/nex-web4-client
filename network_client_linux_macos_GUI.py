from scapy.all import *
from tkinter import *
from threading import Thread
from packet_manager import PacketManager


# Global variable to store api key
apiKey = None
# Global variable to control whether the sniff function should continue running
running = True
# Global variable to store api json response message
apiResponseMessage = None
# Global variable to store tkinter textarea for printing
text = None

# print function for tkinter GUI
def printGUI(string):
  global text
  if(text):
    text.insert('1.0', '{}\n'.format(string))
  else:
    print(string)


pm = PacketManager(apiKey, printGUI, apiResponseMessage)
packet_callback = pm.packet_callback


# GUI
root = Tk()
root.geometry("400x300")
root.configure(bg='black')
root.title("The NEX Web4 Client")


def start_sniff():
  # grab apikey from input
  global apiKey
  apiKey = apikey_entry.get()
  pm.updateApiKey(apiKey)
  printGUI(f'API key: {apiKey}')

  if not apiKey:
    printGUI("Please enter an API key.")
    return

  # Disable the start button while the sniff function is running
  start_button.config(state=DISABLED)

  # Start the sniff function in a separate thread
  t = Thread(target=sniff_thread)
  t.start()


def stop_sniff(packet):
  # Return True to stop sniffing when the 'running' flag is False
  global apiResponseMessage
  if(apiResponseMessage == 'Unauthorized'):
    printGUI("Please enter a valid API key.")
    return True

  # Return True to stop sniffing when the 'running' flag is False
  return not running


def sniff_thread():
  try:
    # Sniff packets until the 'stop_sniff' function returns True
    sniff(prn=packet_callback, store=0, stop_filter=stop_sniff)
    # Re-enable the start button when the sniff function stops
    start_button.config(state=NORMAL)
  except ExceptionType:
      printGUI(ExceptionType)

def Close():
    global running
    # Set the 'running' flag to False to stop the sniff function
    running = False
    # Destroy the Tkinter window
    root.destroy()


start_button = Button(root, text="Start", command=start_sniff)
start_button.pack(pady=10)
start_button.configure(bg='black', fg='lime')

apikey_label = Label(root, text="Enter your API key:")
apikey_label.pack()
apikey_label.configure(bg='black', fg='lime')
apikey_entry = Entry(root)
apikey_entry.pack()

exit_button = Button(root, text="Stop", command=Close)
exit_button.pack(pady=20)
exit_button.configure(bg='black', fg='lime')

text = Text(root)
text.pack()
text.configure(bg='black', fg='lime')

# Run the GUI
root.mainloop()