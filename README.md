# Icarus
An exploit for Chrome devices which allows people to unenroll devices with device management interception using a proxy and a custom Certificate Authority.  

### WARNING
> [!IMPORTANT]
> DO NOT USE ANY PUBLIC IP ADDRESSES FOR ICARUS AS A PROXY, YOU WILL RISK YOUR DATA and YOU WILL BE REMOTELY COMPROMISED.<br><br>
> ANYTHING GOOGLE CAN REMOTELY PERFORM ON YOUR DEVICE, ICARUS CAN BE USED TO DO. AN EXAMPLE OF THIS IS INSTALL EXTENSIONS, SPY, USE YOUR CAMERA, REMOTE INTO YOUR DEVICE, GET YOUR PASSWORDS, AND MORE.<br><br>
> ONLY SELF HOST ICARUS, NEVER USE A PUBLIC SERVER!
> -UNRETAINED

## USING PREBUILTS
GET A PREBUILT @ [MY FILE HOST](https://dl.fanqyxl.net/ChromeOS/Prebuilts/Icarus) OR [KXTZ'S FILE HOST](https://dl.kxtz.dev)
FLASH IT TO YOUR USB USING RUFUS, BALENAETCHER, OR CHROMEBOOK RECOVERY UTILITY

FOLLOW THE SERVER SETUP INSTRUCTIONS
## Setup and installation instructions
Clone the repo with `git clone --recursive https://github.com/fanqyxl/icarus` and change directory to it.

Set up the environment by running the following commands (Make sure you have python3, python3-venv, and protobuf installed beforehand):

- `make build-packed-data`

Before continuing, open Chrome on your build machine and go to chrome://components. Press CTRL + F and search for "PKIMetadata". Once you find it, press "Check for Updates". Make sure it says up-to-date before continuing (and that the version is below 9999.)
  
- `bash scripts/create_out.sh myCA.der`

After doing this the output directory (from here on reffered to as PKIMetadata) will be generated, which is the custom Certificate Authority.

Now, to modify the shim with the generated PKIMetadata (THIS WILL OVERWRITE YOUR SHIM) :

- `sudo bash modify.sh <shim path>`

Now boot the shim, and Icarus will attempt to modify your stateful partition.

### Server setup
Requirements: npm, node  

Linux:
Run `make start-server` to start your proxy, then continue with the instructions below.

Windows:
GET A PREBUILT FROM THE RELEASES TAB, AND RUN IT.

## USING MY PUBLIC SERVER
AGAIN, PLEASE SELF HOST. THIS IS ONLY IF YOU HAVE NO OTHER CHOICE!!

IP: 72.80.65.133

PORT: 8126

## Setup and installation instructions, continued
Reboot the device. You'll boot into verified mode. Once you have your server running, open the network configuration by clicking the lower right button (it will show the date), connecting to wifi, and then change the proxy settings accordingly.

- Set proxy settings to manual
- Set HTTPS IP to the IP you used to host the proxy server. 
- Resume setup and your device will unenroll. 

## Troubleshooting
<details>
  <summary>My device says "Can't reach Google"!</summary>
  
  - Make sure your device and the server are connected to the same network
  - If that didn't work, powerwash your device and re-run the modified shim, and keep the server running.
</details>

## HELP PLEASE
* PLEASE DONT ANNOY WRITABLE/UNRETAINED FOR HELP OR DM ME, KXTZ, OR COSMICDEV
* FOR HELP, YOU CAN PING ME IN MY [DISCORD SERVER](discord.gg/FF6Evz2gwr) OR TN. SAME FOR KXTZ AND COSMIC

## New Credits
- [kxtzownsu](https://github.com/kxtzownsu) - rolling ssl keys
- [cosmicdevv](https://github.com/cosmicdevv) - creating icarus lite
- [fanqyxl](https://github.com/fanqyxl) - maintaining repo, emotional support, testing :3 

## Original Credits
- [MunyDev](https://github.com/MunyDev) - Creating this exploit
- [Archimax](https://github.com/EnterTheVoid-x86) - Cleaning up get_original_data.sh and inshim.sh + README changes
- [r58Playz](https://github.com/r58Playz) - General bash script improvements
- [Akane](https://github.com/genericness) - Help with SSL, general advice, and README changes
