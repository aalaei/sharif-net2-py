# sharif-net2-py

A simple python script for sharif net2 system

## Download Latest Built binary
### Linux:
```bash
mkdir -p ~/.local/bin/
export PATH=$PATH:~/.local/bin/
curl -sL https://github.com/aalaei/sharif-net2-py/releases/latest/download/net2_lin > ~/.local/bin/net2
chmod +x ~/.local/bin/net2
```
you may need to add `export PATH=$PATH:~/.local/bin/` to your .bashrc or .zshrc

### Windows:
```cmd
curl -sL -o net2.exe https://github.com/aalaei/sharif-net2-py/releases/latest/download/net2_win
... add path environment variable
```

### Mac:
```bash
curl -sL -o net2 https://github.com/aalaei/sharif-net2-py/releases/latest/download/net2_mac
chmod +x net2
... add path environment variable
```

## (Alternative) Install reqiurements and Run python script
Use the package manager [pip](https://pip.pypa.io/en/stable/) to install reqirements.txt.

```bash
git clone https://github.com/aalaei/sharif-net2-py.git
cd sharif-net2-py
pip3 install -r requrements.txt
```

## Usage
```bash
net2 -h
usage: connect_sharif [-h] [-d] [-C] [-c] [-f] [-x] [-i {Auto,Smart,br-085cb9faf50c,br-69a00c289746,br-7a4882b2a67c,docker0,enp3s0,lo,veth21bfd87,vmnet1,vmnet8}] [-v] [-a ACCOUNT] [-A] [-l]

Sharif Net2 Script

options:
  -h, --help            show this help message and exit
  -d, --Disconnect      Disconnect from net2
  -C, --Connect         Connect to your net2 account[Activated by Default]
  -c, --Check           Check Account Balance
  -f, --ForceLogin      Force Login(Logout from all other devices and login this device
  -x, --Disconnect-All  Disconnect from All Devices
  -i {Auto,Smart,br-085cb9faf50c,br-69a00c289746,br-7a4882b2a67c,docker0,enp3s0,lo,veth21bfd87,vmnet1,vmnet8}, --Interface {Auto,Smart,br-085cb9faf50c,br-69a00c289746,br-7a4882b2a67c,docker0,enp3s0,lo,veth21bfd87,vmnet1,vmnet8}
                        Interface Name[Default Smart]
  -v, --Verbose         Verbose
  -a ACCOUNT, --Account ACCOUNT
                        Select Account
  -A, --Add-New-Account
                        Add new Account
  -l, --List-Accounts   List Accounts

```
*Note:* All credentials are stored in pass.json without any cryptography. So be careful about your pass.json file.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
