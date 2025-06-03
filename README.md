# Icarus Revived + Icarus Lite

> FOR ALL INSTRUCTIONS, MAKE SURE YOUR V125 - V127 
> Downgrade Images Can Be Found @ [cros.tech](https://cros.tech)
> Instructions To Downgrade Can Be Found @ [cros.tech kajig](https://discord.com/channels/419123358698045453/1019643873032675399)

# Using Prebuilts:

**Keyrolled Instructions:**

OTA (Over the Air)

**Requirements:**

* WiFi
* Keyrolled Chromebook (unable to boot shims)
* Disk Layout V3 (able to boot into [badapple](https://github.com/applefritter-inc/BadApple))

**Steps:**

* Enter Developer Mode
* Once You Reach The Block Screen, Enter Dev Mode Again
* Select "Internet Recovery"
* Now, Connect To Your WiFi and DO NOT CONTINUE!!
* Now Run Control + Alt + F3
* Run ```curl -SLk cdn.fanqyxl.net/icarus_ota.sh | sh```

**USB Instructions:**

**Requirements:**

* 8 Gig or Bigger USB 
* A Laptop to Flash the Image 
* Keyrolled Chromebook (unable to boot shims)
* Disk Layout V3 (able to boot into [badapple](https://github.com/applefritter-inc/BadApple))

**Steps:**

* Enter Developer Mode
* Once You Reach The Block Screen, Enter Dev Mode Again
* Select "Internet Recovery"
* Now Run Control + Alt + F3
* Plug In Your USB
* Find Your USB Using ```fdisk -l```
* Mount The Image Using ```mkdir /icarus && mount /dev/sdX /icarus``` Replacing X With Your USB
* Now Run ```cd /icarus && ./icarus_ba.sh```

**Keyrolled Dedede Instructions**

* Instructions can be found [here](https://github.com/HarryJarry1/dededeicarus)

**Non Keyrolled Instructions:**

**Requirements:**

* 8 Gig or Bigger USB 
* A Laptop to Flash the Image

**Steps:**

* Download Either A [Legacy](https://dl.fanqyxl.net/ChromeOS/Prebuilts/Sh1mmer/Legacy) or [Modern](https://dl.fanqyxl.net/ChromeOS/Prebuilts/Sh1mmer/Modern) Shim For Your Board
* Go Into Payloads
* Select the Icarus Payload
* Once Done, Reboot Your Chromebook

# Server Setup

**Requirements:**

* Python 3.8 or Higher
* Git

**Setup:**

* Clone This Repo Using ```git clone https:github.com/fanqyxl/icarus```
* Navigate to The Downloaded Repo Using ```cd icarus```
* Install Dependencies using ```pip install -r requirements.txt/pip3 install -r requirements.txt```.
* On Some Distros, pip may not work correctly, so run ```sudo apt install python3-protobuf python3-requests python3-openssl python3-cryptography```
* Run python3 main.py

# Using The Server

* Once Back In crOS, Click The Time At The Bottom Right
* Connect to Your WiFI Using the Quick Settings, And Edit Proxy Settings
* Set "Connection Type" to Manual
* Set the "Secure HTTP" IP address to the IP Icarus Lite Gives You
* Set the "Secure HTTP" port to the port Icarus Lite gives you
* Click "Save"
* Continue on with setup

# Building Your Own Shims

* To Build Your Own Shims, Use The Instructions At The [Sh1mmer Repo](http://github.com/MercuryWorkshop/Sh1mmer?tab=readme-ov-file#building-a-beautiful-world-shim)

# Help Please!!

For Help, You Can Either:

**Ask in My [Discord Server](https://discord.gg/FF6Evz2gwr)**
**Or Ping Me Here**

# [Repo](https://github.com/fanqyxl/icarus)

# Credits 
* [fanqyxl](https://fanqyxl.net) Prebuilts, Maintaing Icarus
* [cosmicdevv](https://github.com/cosmicdevv) Writing Icarus-Lite
* [appleflyer](https://github.com/appleflyerv3) Badapple + Badapple-Icarus
* [MunyDev](https://github.com/MunyDev) Discovering and Creating Original Icarus
* All Other Contributors