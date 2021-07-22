# mDHCP

This project contains a DHCP Server and a simulation of communication between DHCP client and server.
The server handles multiple clients on a separated thread and also the client can handle multiple servers.

DHCP uses UDP protocol, so we implemented a multiplexing mechanism ny queues.

# Run the Project

First run `dhcpserver.py` file. You will see this message:

```
DHCP server is starting...

Wait DHCP discovery.
```

Then run the `dhcpclient.py`. It broadcasts the discovery message and waits for the offer.
After receiving offer sends the request and waits for ack. Finally, the client shows the IP
address which got from server.

Results are like this:
```
DHCP client is starting...

Sent DHCP discovery.
Receive DHCP offer.
Send DHCP request.
Receive DHCP ack.

IP Address: 192.168.1.10 
```

# More Features

The server can reserve some addresses for some devices with specific mac address.

The server can filter some mac addresses.

The server has a `configs.json` file in which settings can be changes. Settings like
IP range, Lease Time, etc.
