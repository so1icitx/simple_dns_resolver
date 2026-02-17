
# Simple DNS Recursive Server

A recursive DNS resolver written entirely from scratch in Python. Instead of using high-level DNS libraries, this project uses raw UDP sockets to manually parse packets and resolve domains by talking directly to the internet's Root, TLD, and Authoritative nameservers.

## Current State & Limitations

This project was written as a conceptual proof-of-concept to understand how DNS works at the raw byte level. I am aware it is not perfect and is missing some important features like:

* **Complex Glue Records:** Standard lookups work perfectly, but it currently struggles to troubleshoot and resolve missing nameserver IPs if they belong to completely separate domains.
* **No TCP Support:** The server only supports standard 512-byte UDP payloads. If a response is too large and gets truncated, it does not yet know how to fall back to a TCP connection.
* **No Caching:** Every request performs a full lookup from the Root servers instead of remembering past answers(but this was intended as i wanted to see how the recursion worked).

## Getting Started

### Prerequisites

* Python 3.x


### Installation & Execution

1. Clone the repository and open the folder:

```bash
git clone https://github.com/yourusername/simple-dns-resolver.git
cd simple-dns-resolver

```

2. Start the DNS server:

```bash
python3 main.py

```

> The server will begin listening for incoming traffic on local port 53, and might require admin or root privileges


### Testing the Server

Once the server is running, open a separate terminal window. You can use `nslookup` to force your computer to ask your Python script for the IP address instead of your normal internet provider.

```bash
nslookup google.com 127.0.0.1

```

You should see your Python script output the routing process, and the `nslookup` window will print the final IP address.
