# Icarus
An exploit for Chrome devices which allows people to unenroll devices with device management interception using a proxy and a custom Certificate Authority.  

### WARNING
> [!IMPORTANT]
> DO NOT USE ANY PUBLIC IP ADDRESSES FOR ICARUS AS A PROXY, YOU WILL RISK YOUR DATA and YOU WILL BE REMOTELY COMPROMISED.<br><br>
> ANYTHING GOOGLE CAN REMOTELY PERFORM ON YOUR DEVICE, ICARUS CAN BE USED TO DO. AN EXAMPLE OF THIS IS INSTALL EXTENSIONS, SPY, USE YOUR CAMERA, REMOTE INTO YOUR DEVICE, GET YOUR PASSWORDS, AND MORE.<br><br>
> ONLY SELF HOST ICARUS, NEVER USE A PUBLIC SERVER!
> -UNRETAINED
## REQUIREMENTS
* KV4 OR LOWER CHROMEBOOK
* V127 - V125 (YOU CAN DOWNGRADE USING IMAGES @ https://chrome100.dev)
* A USB DRIVE
* A NON KEYROLLED CHROMEBOOK (SHIMS REQUIRED!!)

## USING PREBUILTS
* GET A PREBUILT FROM [MY FILE HOST](https://dl.fanqyxl.net/ChromeOS/Prebuilts/Icarus)
* FLASH IT TO YOUR USB USING RUFUS, BALENAETCHER, OR CHROMEBOOK RECOVERY UTILITY
* BOOT THE SHIM
* FOLLOW THE SERVER SETUP INSTRUCTIONS

**The rest of the server setup instructions here will assume you're running native Linux, not WSL, not Crostini / Linux on ChromeOS, as it is not supported**

## Server setup
Requirements: python3

> [!IMPORTANT]
> Windows users need to use the exe file in the [releases](https://github.com/fanqyxl/icarus/releases) tab, then skip to [Setup and installation instructions, continued](https://github.com/fanqyxl/icarus?tab=readme-ov-file#Server-instructions) below

Run `git clone https://github.com/fanqyxl/icarus/`

Cd into the icarus directory

Run `make start-server` to start your proxy, then continue with the instructions below.

## Server instructions
Reboot the device. You'll boot into verified mode. Once you have your server running, open the network configuration by clicking the lower right button (it will show the date), connecting to wifi, and then change the proxy settings accordingly.

- Set proxy settings to manual
- Set HTTPS IP to the IP you used to host the proxy server. 
- Resume setup and your device will unenroll. 

## Making your own shims
Requirements: 
> Linux based machine (wsl wont work, VMs will, crostini also wont work)
> Chrome Installed

Clone the repo with `git clone --recursive https://github.com/fanqyxl/icarus` and change directory to it.

Set up the environment by running the following commands (Make sure you have python3, python3-venv, protobuf, and chrome installed beforehand):

- `make build-packed-data`

Before continuing, open Chrome on the machine your building shims on and go to chrome://components. Press CTRL + F and search for "PKIMetadata". Once you find it, press "Check for Updates". Make sure it says up-to-date before continuing (and that the version is below 9999.)
  
- `bash scripts/create_out.sh myCA.der`

After doing this the output directory (from here on reffered to as PKIMetadata) will be generated, which is the custom Certificate Authority.

Now, to modify the shim with the generated PKIMetadata (THIS WILL OVERWRITE YOUR SHIM) :

- `sudo bash modify.sh <shim path>`

Now boot the shim, and Icarus will attempt to modify your stateful partition.


## Troubleshooting
<details>
  <summary>My device says "Can't reach Google"!</summary>
  
  - Make sure your device and the server are connected to the same network
  - If that didn't work, powerwash your device and re-run the modified shim, and keep the server running.
</details>

## HELP PLEASE
* PLEASE DONT ANNOY WRITABLE/UNRETAINED FOR HELP OR DM ME, KXTZ, OR COSMICDEV
* FOR HELP, YOU CAN PING ME IN MY [DISCORD SERVER](https://discord.gg/FF6Evz2gwr). SAME FOR COSMIC
* YOU CAN ALSO GET HELP IN [TITANIUM NETWORK](https://discord.gg/unblock), PING ME OR COSMIC IN THE ICARUS REVIVED KAJIG

## New Credits
- [kxtzownsu](https://github.com/kxtzownsu) - rolling ssl keys, rewriting bash scripts
- [cosmicdevv](https://github.com/cosmicdevv) - creating icarus lite
- [fanqyxl](https://github.com/fanqyxl) - maintaining repo, emotional support, testing :3
- [AC3](https://github.com/AC3GT) - helping in times of depression and desperate needs 

## Original Credits
- [MunyDev](https://github.com/MunyDev) - Creating this exploit
- [Archimax](https://github.com/EnterTheVoid-x86) - Cleaning up get_original_data.sh and inshim.sh + README changes
- [r58Playz](https://github.com/r58Playz) - General bash script improvements
- [Akane](https://github.com/genericness) - Help with SSL, general advice, and README changes
