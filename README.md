<div align="center">

# 🔴 EDUCATIONAL USE ONLY 🔴

<img src="https://img.shields.io/badge/EDUCATIONAL%20USE%20ONLY-AUTHORIZED%20TESTING%20ONLY-red?style=for-the-badge" alt="Educational Use Only">

**This project is provided strictly for educational, research, and authorized network-security testing.**

**Use it only on systems, servers, IP ranges, and networks that you own or for which you have explicit written permission to test.**

**Do not use this project to impersonate third parties, evade network controls, disrupt services, or send spoofed traffic toward systems you are not authorized to test. You are responsible for complying with all applicable laws, provider policies, and acceptable-use rules.**

</div>

---

# IP-Spoof-test

ابزاری Bash برای بررسی رفتار شبکه در برابر **IP Source Spoofing** در یک محیط آزمایشگاهی، کنترل‌شده و مجاز.

Repository:

```text
KindReYX/IP-Spoof-test
```

Main script:

```text
IP_Spoofing_test.sh
```

این ابزار برای بررسی آزمایشگاهی این موضوع طراحی شده که آیا بسته‌های ICMP با Source IP تغییر‌یافته در مسیر خروجی/ورودی عبور می‌کنند یا توسط میزبان، دیتاسنتر، ISP، فایروال، NAT یا فیلترینگ شبکه Drop/Rewrite می‌شوند.

> این پروژه برای تست امنیت شبکه و تحقیق آموزشی طراحی شده است، نه برای حمله، ناشناس‌سازی، دور زدن محدودیت‌ها یا ارسال ترافیک بدون مجوز.

---

## فهرست مطالب

- [قابلیت‌ها](#قابلیت‌ها)
- [نحوه کار](#نحوه-کار)
- [پیش‌نیازها](#پیشنیازها)
- [سیستم‌عامل‌های مناسب](#سیستمعاملهای-مناسب)
- [نصب](#نصب)
- [اجرای اولیه](#اجرای-اولیه)
- [حالت‌های اجرا](#حالتهای-اجرا)
- [Automated Test](#automated-test)
- [Manual Sender / Receiver](#manual-sender--receiver)
- [تست IP و CIDR](#تست-ip-و-cidr)
- [تست چند IP/CIDR از فایل](#تست-چند-ipcidr-از-فایل)
- [اجرای تست‌های طولانی با screen](#اجرای-تستهای-طولانی-با-screen)
- [خروجی CSV](#خروجی-csv)
- [Debug Mode](#debug-mode)
- [حریم خصوصی و اطلاعات حساس](#حریم-خصوصی-و-اطلاعات-حساس)
- [Cleanup](#cleanup)
- [عیب‌یابی](#عیبیابی)
- [محدودیت‌ها](#محدودیتها)
- [نکات امنیتی](#نکات-امنیتی)
- [License](#license)

---

## قابلیت‌ها

اسکریپت فعلی شامل قابلیت‌های زیر است:

- تست دوطرفه بین دو سرور
  - Direct: Local → Remote
  - Reverse: Remote → Local
- تست دستی Sender / Receiver
- پشتیبانی از IPv4
- پشتیبانی از CIDR
- انتخاب تعداد Sample از CIDR
- پشتیبانی از فایل شامل چند IP یا CIDR
- Capture بسته‌های ICMP با `tcpdump`
- استفاده از قوانین موقت `iptables`
- استفاده از `nftables` در برخی مسیرهای تست
- بررسی `conntrack`
- استفاده از `Scapy`
- استفاده از `nping`
- خروجی CSV
- Debug mode
- Cleanup خودکار قوانین موقت
- پشتیبانی از اجرای Batch برای تعداد زیاد IP/CIDR

---

## نحوه کار

در Automated mode ابزار از دو ماشین Linux استفاده می‌کند:

```text
+--------------------------+              +--------------------------+
| Local / Test Server      |              | Remote / Test Server     |
|                          |              |                          |
| IP_Spoofing_test.sh                  | <----------> | SSH + tcpdump            |
| iptables / tcpdump       |              | iptables / nftables      |
| Scapy / nping            |              | Scapy / nping            |
+--------------------------+              +--------------------------+
```

به‌صورت کلی:

1. ارتباط عادی بین دو سرور بررسی می‌شود.
2. Packet Capture فعال می‌شود.
3. Baseline بدون Spoof ساخته می‌شود.
4. تست Source IP آزمایشی اجرا می‌شود.
5. در صورت نیاز روش‌های جایگزین مانند Raw Packet بررسی می‌شوند.
6. نتیجه Capture تحلیل می‌شود.
7. نتیجه در ترمینال و فایل CSV نمایش داده می‌شود.
8. Ruleهای موقت Cleanup می‌شوند.

نتیجه می‌تواند نشان دهد که:

- Source آزمایشی روی مقصد دیده شده است.
- Source توسط NAT بازنویسی شده است.
- Packet در مسیر Drop شده است.
- Capture یا ارتباط SSH مشکل داشته است.
- تست به‌صورت کامل قابل نتیجه‌گیری نبوده است.

> نتیجه فقط مربوط به همان مسیر، همان سرورها، همان Providerها و همان زمان تست است و نباید به کل اینترنت یا کل شبکه یک Provider تعمیم داده شود.

---

## پیش‌نیازها

### حداقل نیازمندی‌ها

روی سروری که `IP_Spoofing_test.sh` روی آن اجرا می‌شود:

- Linux
- Bash
- Root access
- `ip`
- `iptables`
- `ping`
- `tcpdump`
- `python3`

برای Automated mode نیز معمولاً موارد زیر لازم هستند:

- `ssh`
- `sshpass`
- `conntrack`
- `nping`
- `nft`
- Python Scapy

اسکریپت **قبل از نمایش منو و اجرای تست** Dependencyهای محلی را بررسی می‌کند و در صورت نبودن، تلاش می‌کند آن‌ها را با Package Manager سیستم به‌صورت خودکار نصب کند.

اگر نصب خودکار ممکن نبود یا ترجیح می‌دهید پکیج‌ها را دستی نصب کنید، فایل `requirements.txt` در Repository شامل دستورهای نصب دستی برای Distributionهای پشتیبانی‌شده است.

---

## دسترسی Root

به دلیل استفاده از Packet Capture، Raw Packet و Ruleهای NAT، اسکریپت باید با Root اجرا شود.

```bash
sudo bash IP_Spoofing_test.sh
```

یا:

```bash
chmod +x IP_Spoofing_test.sh
sudo ./IP_Spoofing_test.sh
```

---

## سیستم‌عامل‌های مناسب

بهترین سازگاری معمولاً روی Linux Server است.

نمونه‌ها:

- Debian
- Ubuntu
- Fedora
- Rocky Linux
- AlmaLinux
- CentOS-compatible
- Arch Linux

برای Automated mode بهتر است هر دو سمت Linux باشند.

---

# نصب

## روش پیشنهادی: Clone از GitHub

```bash
git clone https://github.com/KindReYX/IP-Spoof-test.git
cd IP-Spoof-test
chmod +x IP_Spoofing_test.sh
```

سپس:

```bash
sudo ./IP_Spoofing_test.sh
```

در اولین اجرا، اسکریپت Dependencyهای Missing را شناسایی و در صورت امکان نصب می‌کند. برای نصب دستی نیز فایل زیر را ببینید:

```text
requirements.txt
```

نمایش راهنمای نصب دستی:

```bash
cat requirements.txt
```

---

## نصب خودکار Dependencyها

نیازی نیست قبل از اجرای معمول پروژه همه پکیج‌ها را دستی نصب کنید. کافی است:

```bash
chmod +x IP_Spoofing_test.sh
sudo ./IP_Spoofing_test.sh
```

اسکریپت Package Manager سیستم را تشخیص می‌دهد، Dependencyهای Missing را نصب می‌کند و سپس آن‌ها را دوباره Verify می‌کند. در صورتی که یک Dependency ضروری همچنان موجود نباشد، تست شروع نمی‌شود و خطا نمایش داده می‌شود.

> نصب خودکار به دسترسی Root و دسترسی Repositoryهای سیستم به اینترنت نیاز دارد.

### نصب دستی

برای نصب دستی تمام موارد موردنیاز، فایل `requirements.txt` را باز کنید:

```bash
cat requirements.txt
```

---

## Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y \
  bash \
  iproute2 \
  iptables \
  nftables \
  iputils-ping \
  tcpdump \
  conntrack \
  nmap \
  python3 \
  python3-pip \
  python3-scapy \
  openssh-client \
  sshpass \
  screen
```

بررسی نصب:

```bash
command -v ip
command -v iptables
command -v nft
command -v tcpdump
command -v ping
command -v python3
command -v conntrack
command -v nping
command -v ssh
command -v sshpass
command -v screen
```

---

## Fedora / Rocky / AlmaLinux

```bash
sudo dnf install -y \
  iproute \
  iptables \
  nftables \
  iputils \
  tcpdump \
  conntrack-tools \
  nmap \
  python3 \
  python3-pip \
  openssh-clients \
  screen
```

در صورت نبود Scapy در Repository سیستم، آن را از Package Manager توزیع یا در محیط Python مجزا نصب کنید.

---

## Arch Linux

```bash
sudo pacman -S --needed \
  iproute2 \
  iptables \
  nftables \
  iputils \
  tcpdump \
  conntrack-tools \
  nmap \
  python \
  openssh \
  sshpass \
  screen
```

---

# اجرای اولیه

بعد از Clone:

```bash
cd IP-Spoof-test
chmod +x IP_Spoofing_test.sh
sudo ./IP_Spoofing_test.sh
```

اگر ترجیح می‌دهید مستقیم با Bash اجرا شود:

```bash
sudo bash IP_Spoofing_test.sh
```

برای فعال‌کردن Debug از Argument نیز می‌توانید استفاده کنید:

```bash
sudo bash IP_Spoofing_test.sh --debug
```

یا:

```bash
sudo bash IP_Spoofing_test.sh -d
```

---

# حالت‌های اجرا

اسکریپت برای تست‌های مختلف طراحی شده و می‌تواند شامل حالت‌های Automated و Manual باشد.

در حالت Automated معمولاً اطلاعات زیر از شما درخواست می‌شود:

- Remote Server IP
- SSH Port
- SSH Username
- SSH Password
- Local Server IP
- Spoof Source IP / CIDR / List file
- Test direction
- Debug mode
- Confirmation

---

# Automated Test

Automated mode برای تست دو Server طراحی شده است.

سناریوی نمونه:

```text
Local Test Server
        |
        | SSH / ICMP Test
        |
Remote Test Server
```

## اطلاعات SSH

برای Remote Server باید اطلاعات SSH معتبر داشته باشید.

نمونه Placeholder:

```text
Remote Server IP: 203.0.113.10
SSH Port: 22
SSH Username: root
```

Password در زمان اجرا وارد می‌شود.

> هیچ Password، Private Key، Token یا Credential واقعی را داخل Repository، README، Issue، Screenshot یا Log عمومی Commit نکنید.

---

## انتخاب Direction

اسکریپت می‌تواند تست‌ها را در Directionهای مختلف اجرا کند:

```text
1) Both directions
2) Direct only
3) Reverse only
```

### Direct

```text
Local -> Remote
```

### Reverse

```text
Remote -> Local
```

### Both

هر دو Direction پشت‌سرهم بررسی می‌شوند.

---

# Manual Sender / Receiver

در حالت Manual می‌توانید یک سمت را به‌عنوان Sender و سمت دیگر را برای مشاهده Packetها استفاده کنید.

برای تست آزمایشگاهی، فقط از IPها و سیستم‌هایی استفاده کنید که مالک آن‌ها هستید یا اجازه صریح تست دارید.

نمونه IPهای امن برای Documentation:

```text
192.0.2.10
198.51.100.20
203.0.113.30
```

این Rangeها برای Documentation رزرو شده‌اند و بهتر است به‌جای IP واقعی در README و Screenshot استفاده شوند.

---

# تست IP و CIDR

ابزار می‌تواند یک IPv4 یا CIDR دریافت کند.

نمونه Single IP:

```text
192.0.2.10
```

نمونه CIDR:

```text
198.51.100.0/24
```

برای CIDR می‌توانید تعداد IPهای Sample را مشخص کنید.

مثلاً:

```text
3
```

یا:

```text
20
```

در صورت پشتیبانی حالت کامل:

```text
all
```

> روی Rangeهای بزرگ، تعداد Packetها و مدت تست می‌تواند بسیار بیشتر شود. فقط در Lab یا Infrastructure مجاز استفاده کنید.

---

# تست چند IP/CIDR از فایل

برای Batch Test می‌توانید یک فایل Text بسازید.

مثال:

```text
192.0.2.10
192.0.2.20
198.51.100.0/28
203.0.113.0/29
```

Comment نیز قابل استفاده است:

```text
# Test hosts
192.0.2.10
192.0.2.20

# Lab CIDRs
198.51.100.0/28
203.0.113.0/29
```

مثلاً فایل را با نام زیر ذخیره کنید:

```text
targets.txt
```

سپس هنگام Prompt فایل:

```text
./targets.txt
```

یا:

```text
@./targets.txt
```

وارد کنید.

---

# اجرای تست‌های طولانی با screen

اگر تعداد IPها زیاد است، CIDR بزرگی تست می‌کنید یا احتمال دارد SSH Session شما قطع شود، بهتر است تست را داخل `screen` اجرا کنید.

`screen` باعث می‌شود Process حتی بعد از قطع‌شدن SSH Session نیز روی Server ادامه پیدا کند.

## نصب screen

Debian / Ubuntu:

```bash
sudo apt update
sudo apt install -y screen
```

Fedora / Rocky / AlmaLinux:

```bash
sudo dnf install -y screen
```

Arch Linux:

```bash
sudo pacman -S screen
```

---

## ساخت یک Screen Session

ابتدا وارد Directory پروژه شوید:

```bash
cd IP-Spoof-test
```

یک Session با نام مشخص بسازید:

```bash
screen -S ip-spoof-test
```

بعد داخل Screen اسکریپت را اجرا کنید:

```bash
sudo ./IP_Spoofing_test.sh
```

یا:

```bash
sudo bash IP_Spoofing_test.sh
```

---

## خارج‌شدن از Screen بدون Stop کردن تست

برای Detach کردن Session:

```text
Ctrl + A
```

سپس:

```text
D
```

یعنی ابتدا `Ctrl+A` و بعد کلید `D`.

بعد از Detach، تست در Background ادامه پیدا می‌کند.

---

## دیدن Screenهای فعال

```bash
screen -ls
```

نمونه Output:

```text
There is a screen on:
    12345.ip-spoof-test
```

---

## برگشتن به Screen

```bash
screen -r ip-spoof-test
```

اگر فقط یک Session دارید:

```bash
screen -r
```

اگر Session به شکل Attached باقی مانده بود:

```bash
screen -d -r ip-spoof-test
```

---

## پایان Screen

اگر تست تمام شده و می‌خواهید Session را ببندید:

داخل Screen:

```bash
exit
```

یا از بیرون:

```bash
screen -S ip-spoof-test -X quit
```

---

## پیشنهاد برای لیست‌های بزرگ

برای Batchهای طولانی:

```bash
cd IP-Spoof-test
screen -S ip-spoof-test
sudo bash IP_Spoofing_test.sh
```

بعد از شروع تست:

```text
Ctrl+A
D
```

و بعداً:

```bash
screen -r ip-spoof-test
```

این روش برای تست‌های طولانی روی SSH بسیار مناسب‌تر است.

---

# خروجی CSV

اسکریپت نتیجه را در دو فایل ثابت ذخیره می‌کند:

```text
spoof_summary.csv
spoof_full.csv
```

## `spoof_summary.csv`

خلاصه نتیجه تست را نگه می‌دارد.

ممکن است شامل اطلاعاتی مانند موارد زیر باشد:

- Timestamp
- Source test IP/CIDR
- Local IP
- Remote IP
- Direction
- Result
- Status
- Packet count
- Proof status

## `spoof_full.csv`

جزئیات بیشتر Per-IP را نگه می‌دارد.

برای Batch/CIDR این فایل جهت بررسی دقیق‌تر نتیجه هر IP مفید است.

> این فایل‌ها ممکن است IPهای واقعی محیط آزمایش شما را شامل شوند. قبل از Upload کردن در GitHub، Issue، Discord، Telegram یا هر محیط عمومی آن‌ها را Sanitize کنید.

---

# Debug Mode

برای بررسی خطاها می‌توانید Debug mode را فعال کنید.

از CLI:

```bash
sudo bash IP_Spoofing_test.sh --debug
```

یا:

```bash
sudo bash IP_Spoofing_test.sh -d
```

Debug mode ممکن است اطلاعاتی مانند موارد زیر ثبت کند:

- Command output
- Network interface information
- Routing information
- iptables / nftables state
- Capture logs
- Remote diagnostics
- IP addresses
- System information

به همین دلیل Debug Log را عمومی منتشر نکنید مگر اینکه ابتدا اطلاعات حساس حذف شده باشند.

---

# حریم خصوصی و اطلاعات حساس

این Repository نباید شامل اطلاعات واقعی محیط Production باشد.

موارد زیر را Commit نکنید:

```text
Passwords
Private Keys
API Tokens
SSH Keys
Real customer IPs
Internal IP maps
Provider credentials
Debug logs containing secrets
Production hostnames
Personal information
```

برای README و Issueها از Placeholder استفاده کنید:

```text
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
```

نمونه:

```text
Local Server : 192.0.2.10
Remote Server: 198.51.100.20
Test Source  : 203.0.113.30
```

---

## پیشنهاد `.gitignore`

می‌توانید این موارد را داخل `.gitignore` قرار دهید:

```gitignore
spoof_summary.csv
spoof_full.csv
*.log
debug/
logs/
targets-private.txt
*.key
*.pem
.env
.env.*
```

---

# Cleanup

اسکریپت برای Ruleهای موقت شبکه Cleanup دارد.

در حالت عادی هنگام Exit تلاش می‌شود Ruleهای Temporary حذف شوند.

با این حال، بعد از Crash، Kill ناگهانی یا Reboot بهتر است Rules را بررسی کنید.

بررسی NAT:

```bash
sudo iptables -t nat -L POSTROUTING -n -v --line-numbers
```

بررسی nftables:

```bash
sudo nft list ruleset
```

بررسی Processهای tcpdump:

```bash
ps aux | grep tcpdump
```

---

# عیب‌یابی

## خطای Root

اگر پیام مربوط به Root دریافت کردید:

```bash
sudo bash IP_Spoofing_test.sh
```

---

## `sshpass` پیدا نمی‌شود

Debian / Ubuntu:

```bash
sudo apt install -y sshpass
```

---

## `tcpdump` پیدا نمی‌شود

```bash
sudo apt install -y tcpdump
```

---

## `nping` پیدا نمی‌شود

`nping` معمولاً همراه Nmap نصب می‌شود:

```bash
sudo apt install -y nmap
```

---

## `conntrack` پیدا نمی‌شود

```bash
sudo apt install -y conntrack
```

---

## Scapy در دسترس نیست

روی Debian / Ubuntu:

```bash
sudo apt install -y python3-scapy
```

---

## SSH Connection Failed

موارد زیر را بررسی کنید:

- Remote IP
- SSH Port
- Username
- Password
- Firewall
- SSH daemon
- Provider ACL
- Security Group

نمونه تست:

```bash
ssh -p 22 root@203.0.113.10
```

---

## Baseline کار نمی‌کند

اگر Baseline عادی هم Packet دریافت نمی‌کند، نتیجه Spoof Test قابل اعتماد نیست.

موارد زیر را بررسی کنید:

- ICMP filtering
- tcpdump permission
- Routing
- Firewall
- Wrong interface
- Wrong Local/Remote IP
- Cloud Security Group
- Provider filtering

---

## Result = REAL IP

اگر Destination به‌جای Source آزمایشی، IP واقعی Server را می‌بیند، ممکن است NAT یا MASQUERADE Source را Rewrite کرده باشد.

مواردی که باید بررسی شوند:

```text
iptables NAT order
nftables
Docker rules
Container networking
conntrack
Provider NAT
Tunnel/VPN
Policy routing
```

---

## Result = BLOCKED / DROPPED

این نتیجه می‌تواند به این معنی باشد که Packet در یکی از لایه‌های زیر Drop شده است:

- Local host
- Hypervisor
- Datacenter edge
- ISP
- Transit network
- Destination filtering

از یک تست منفرد نمی‌توان دقیقاً مشخص کرد Drop در کدام نقطه انجام شده است.

---

# محدودیت‌ها

- تمرکز اصلی ابزار روی IPv4 است.
- نتیجه تست به Routing واقعی بستگی دارد.
- NAT می‌تواند نتیجه را تغییر دهد.
- Container networking می‌تواند روی Rule order اثر بگذارد.
- بعضی Providerها Raw Packet را محدود می‌کنند.
- بعضی Providerها Source Spoofing را در Hypervisor یا Edge فیلتر می‌کنند.
- ICMP ممکن است جداگانه Filter شده باشد.
- نتیجه یک Server الزاماً نماینده کل Provider نیست.
- اجرای CIDRهای بزرگ Resource و زمان بیشتری مصرف می‌کند.

---

# نکات امنیتی

- فقط روی Infrastructure تحت مالکیت یا مجوز خود تست کنید.
- از Source IP اشخاص یا سیستم‌های واقعی دیگر استفاده نکنید.
- از Rangeهای Documentation یا Range آزمایشگاهی خودتان استفاده کنید.
- Logهای Debug را قبل از انتشار Sanitize کنید.
- فایل CSV را قبل از Share بررسی کنید.
- Passwordها را داخل Script یا README ذخیره نکنید.
- از Repository عمومی برای نگهداری Credential استفاده نکنید.
- در محیط Production بدون Change Window و Backup Ruleها تست نکنید.
- قبل و بعد از تست Firewall/NAT Rules را بررسی کنید.

---

# نمونه Lab امن

نمونه Documentation:

```text
Local server:
192.0.2.10

Remote server:
198.51.100.20

Test source:
203.0.113.30
```

این IPها صرفاً Example هستند.

---

# Repository Structure

نمونه Structure پیشنهادی:

```text
IP-Spoof-test/
├── IP_Spoofing_test.sh
├── README.md
├── requirements.txt
├── .gitignore
└── examples/
    └── targets.example.txt
```

---

# فایل Example Target List

برای Repository می‌توانید یک فایل نمونه بدون اطلاعات واقعی ایجاد کنید:

```text
# examples/targets.example.txt

192.0.2.10
192.0.2.20
198.51.100.0/29
203.0.113.0/29
```

---

# License

---

## Disclaimer

این ابزار بدون Warranty ارائه می‌شود.

استفاده‌کننده مسئول موارد زیر است:

- دریافت مجوز لازم
- رعایت قوانین
- رعایت Terms of Service دیتاسنتر و ISP
- جلوگیری از ارسال ترافیک ناخواسته
- محافظت از Credentialها
- بررسی اثر تست روی Infrastructure

---

<div align="center">

### Made with ❤️ & AI

</div>
