This Python script leverages the Scapy library to scan and identify available Wi-Fi networks. It begins by listing all available network interfaces on the device using the get_interfaces() function, allowing the user to select one. The scan_wifi(iface) function then captures network packets on the specified interface, focusing on Wi-Fi beacon frames that contain network information such as SSID, BSSID, signal strength, channel, and supported data rates. These details are stored in a dictionary and displayed to the user after scanning. The script is designed to run in a command-line environment, prompting the user to select an interface and then presenting detailed information about detected Wi-Fi networks.

How to use this script in your terminal do the following as listed in order below

git clone https://github.com/SleepTheGod/Wifi-Scanner

cd Wifi-Scanner

pip install -r requirements.txt

chmod +x main.py

python main.py
