# Beacon Whisper
Data Exfilteration with Beacon Frames 

# FAQ

## What does this code do?
This code can operate as a transmitter or a receiver. As a transmitter, it firsts sniffs the air for a few seconds and ascertains what the neighbourhood looks like in terms of Beacon Frames.
It then proceeds to exfilterate data that remains hidden in a particular element of the Dot11Elt Layer. The initial profiling is to operate stealthily. The goal is to make this go under the radar of a WiFi IDS. As of date, the real world stealth capability is unknown since it has not been tested against a real world WiFi IDS. 

## How do you use it?
This is an experiment that you can set up in a lab. You will need at least one WiFi card capable of entering monitor mode. You can then run the transmit, and receive on the same machine and see how it works.
Ensure that your wireless card is in monitor mode. You can set it using airmon-ng or any other tool that you like. 

Transmit 
```bash
python main.py transmit /path/to/file wlan0mon
```
Receive
```bash
python main.py receive /path/to/file wlan0mon
```
## Is there a real world use case?
Yes. The capability to exfilterate data in the real world using beacon frames will likely take on the form of the transmitter component being embedded in malware. How to get the malware onto the system, and how to put the infected systems Wireless card into monitor mode is beyond the scope of this project.
I may attempt another project to patch the wireless drivers in memory to enable monitor mode on select chipsets, but for now this is it. 

## Disclaimer
Please use this for educational purposes only. Do not engage in illegal or unethical activities....ever. 
