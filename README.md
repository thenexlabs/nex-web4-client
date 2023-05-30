# NEX Web4 Client App

## Install neccessary packages
1) sudo pip install scapy GPUtil psutil requests

### On EC2 install neccessary packages
1) sudo yum install python3-pip
2) sudo pip install scapy GPUtil psutil requests

## Run from CLI
sudo python3 network_client_linux_macos.py your_apiKey

## Run GUI from CLI
sudo python3 network_client_linux_macos_GUI.py

## Build GUI Executable
sudo pyinstaller --onefile network_client_linux_macos_GUI.py

### On EC2 run executable while disconnected from ssh using tmux
1) sudo yum install tmux
2) tmux new-session -d -s your_session_name 
3) python3 network_client_linux_macos.py your_apiKey
4) Press Ctrl-b, then d. This will detach the current session.

### List tmux sessions
1) tmux ls

### Open tmux session
1) tmux attach -t your_session_name

### End tmux session
1) tmux kill-session -t your_session_name