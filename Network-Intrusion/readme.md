# Snort Network Intrusion Detection System (NIDS)

## 🛡️ Overview
Snort is a powerful, open-source network intrusion detection system (NIDS) that performs real-time traffic analysis and packet logging. It can be used to detect a variety of attacks and probes.

---

## 📦 Requirements

- Linux (Ubuntu/Debian recommended)
- Root privileges
- Build tools (make, gcc, etc.)
- Libpcap and libpcre libraries

---

## 🔧 Installation Steps

### 1. Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install Dependencies
```bash
sudo apt install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev ethtool
```

### 3. Download and Install DAQ
```bash
cd /tmp
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
tar -xvzf daq-2.0.7.tar.gz
cd daq-2.0.7
./configure && make && sudo make install
```

### 4. Download and Install Snort
```bash
cd /tmp
wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
tar -xvzf snort-2.9.20.tar.gz
cd snort-2.9.20
./configure --enable-sourcefire && make && sudo make install
```

### 5. Create Snort Directories
```bash
sudo mkdir -p /etc/snort/rules
sudo mkdir /var/log/snort
sudo mkdir /usr/local/lib/snort_dynamicrules

sudo touch /etc/snort/rules/white_list.rules
sudo touch /etc/snort/rules/black_list.rules
```

### 6. Download Snort Rules
- Register at [https://www.snort.org](https://www.snort.org)
- Download the **Community Rules** or **Registered Rules**
```bash
cd /tmp
wget https://www.snort.org/downloads/community/community-rules.tar.gz
tar -xvzf community-rules.tar.gz
sudo cp community-rules/* /etc/snort/rules
```

---

## ⚙️ Configuration Files

### 1. Snort Configuration
```bash
sudo cp /tmp/snort-2.9.20/etc/* /etc/snort
```

### 2. Edit `/etc/snort/snort.conf`
Update the following variables:
```bash
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules

ipvar HOME_NET any
ipvar EXTERNAL_NET any
```

Make sure rule paths point correctly and all rules you want are included at the bottom:
```bash
include $RULE_PATH/community.rules
```

---

## 🧪 Test Snort

### Test Configuration
```bash
sudo snort -T -c /etc/snort/snort.conf
```

### Run Snort in NIDS Mode
```bash
sudo snort -A console -i eth0 -c /etc/snort/snort.conf -l /var/log/snort
```
> Replace `eth0` with your actual network interface (`ip a` to check).

---

## 📑 Logs

Snort logs will be saved to:
```
/var/log/snort/
```

---

## ✅ Verification

After running Snort:
- Generate some test traffic (`ping`, `nmap`, etc.)
- Check console or log file for alerts

---

## 📚 Resources

- [Snort Official Website](https://www.snort.org)
- [Snort Documentation](https://docs.snort.org/)
- [Community Rules Download](https://www.snort.org/downloads)

---

## 👨‍💻 Author

Maintained by Abhijith MR  
GitHub: [@abhijithmr226](https://github.com/abhijithmr226)  
LinkedIn: [abhijith226linkedin](https://www.linkedin.com/in/abhijithmr226)

---

## 📝 License

This setup is for educational and testing purposes.