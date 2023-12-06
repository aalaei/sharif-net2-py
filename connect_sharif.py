#! /bin/python3
from bs4 import BeautifulSoup
import requests
import json
import os
import base64
import sys
import time
from PIL import Image
import shutil
import re
import climage
import pickle
from persiantools.jdatetime import JalaliDate
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util import connection
import dns.resolver
import argparse
# import ifaddr
# import netifaces
import stdiomask
import ifcfg

from rapidfuzz import fuzz
net2_url='https://net2.sharif.edu/{}'
bw_url='https://bw.ictc.sharif.edu/login'
net_url='https://net.sharif.edu'
net_headers = {
    'Referer': 'https://net.sharif.edu/',
    'Host': 'net.sharif.edu',
    'Accept-Language' : 'en-US,en;q=0.9,fa;q=0.8',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36',
    'X-Requested-With':'XMLHttpRequest'
}

_orig_create_connection = connection.create_connection

def custom_dns_resolver(host):
    if host == 'net2.sharif.edu':
        return '172.17.1.214'
    try:
        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = [
                '81.31.160.34', # NOTE: NS1 sharif
                '81.31.160.35', # NOTE: NS2 sharif
                '172.26.146.34', # NOTE: NS1 net2 sharif
                '172.26.146.35', # NOTE: NS2 net2 sharif
                '208.67.222.222', # NOTE: OpenDNS
                '8.8.8.8'         # NOTE: Google
        ]
        answer = my_resolver.resolve(host)
        return answer[0].address
    except:
        return host

def patched_create_connection(address, *args, **kwargs):
    """Wrap urllib3's create_connection to resolve the name elsewhere"""
    # resolve hostname to an ip address; use your own
    # resolver here, as otherwise the system resolver will be used.
    host, port = address
    hostname = custom_dns_resolver(host)

    return _orig_create_connection((hostname, port), *args, **kwargs)

def init_requests_session(addr:str='') -> requests.Session:
    connection.create_connection = patched_create_connection

    # Suppress only the single warning from urllib3 needed.
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    s=requests.Session()
    s.verify=False
    for prefix in ('http://', 'https://'):
        s.get_adapter(prefix).init_poolmanager(
            # those are default values from HTTPAdapter's constructor
            connections=requests.adapters.DEFAULT_POOLSIZE,
            maxsize=requests.adapters.DEFAULT_POOLSIZE,
            # This should be a tuple of (address, port). Port 0 means auto-selection.
            source_address=(addr, 0),
        )

    return s

def go_to_app_dir(config_file_name='pass.json'):
    # determine if application is a script file or frozen exe
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    elif __file__:
        application_path = os.path.dirname(__file__)

    config_file_name = os.path.join(application_path, config_file_name)
    dname = os.path.dirname(config_file_name)
    os.chdir(dname)

def try_base64(file_content):
    format="plain"
    try:
        file_content=base64.b64decode(file_content.encode()).decode()
        format="base64"
    except Exception as e:
        print("Warning: Credentials are stored as plain text, try to hide them using 'net2 -H'")
    return file_content, format
def get_config_credentials(config_file_name='pass.json'):
    go_to_app_dir(config_file_name)
    try:
        with open(config_file_name) as f:
            file_content=f.read()
            file_content, _=try_base64(file_content)
            try:
                credentials = json.loads(file_content)
            except Exception as e:
                print("Error: Unable to Parse Credentials")
                sys.exit(-1)
    except FileNotFoundError:
        print('Credentials file not found.')
        username, password=get_user_pass_from_input()
        credentials = {username: {'username': username, 'password': password}}
        with open(config_file_name, 'w') as f:
            json.dump(credentials, f)
    return credentials

def get_user_pass_from_input():
    username = input("Please enter your username: ")
    password = stdiomask.getpass(prompt = 'Please enter your password: ')
    return username, password

def manipulate_account(fnc, config_file_name='pass.json'):
    credentials=None
    try:
        with open(config_file_name, 'r') as f:
            file_content=f.read()
            file_content, format=try_base64(file_content)
            credentials = json.loads(file_content)
            credentials=fnc(credentials)
            with open(config_file_name, 'w') as f2:
                cr_str = json.dumps(credentials)
                if format == "base64":
                    cr_str = base64.b64encode(cr_str.encode()).decode()
                f2.write(cr_str)
    except FileExistsError:
        print("Credentials file not found")
    return credentials

def append_new_account(config_file_name='pass.json', _user=None, _pass=None):
    if _user is None and _pass is None:
        _user, _pass = get_user_pass_from_input()
    try:
        def fnc(credentials):
            credentials[_user] = {'username': _user, 'password': _pass}
            return credentials
        manipulate_account(fnc, config_file_name)   
    except Exception as e:
        print("Append failed!", e)
    
def delete_account(user, config_file_name='pass.json'):
    if user=="":
        user = input("Please enter username you want to delete: ")
    credentials=None
    try:
        def del_fnc(credentials):
            del credentials[user]
            return credentials
        inp=""
        while not(inp.lower() == "y" or inp.lower() == "n"):
            inp=input(f"Are you sure you want to delete '{user}' (y/n)? ")
        if inp.lower()=="y":
            manipulate_account(del_fnc, config_file_name)
            print(f"'{user}' was deleted successfully")
    except Exception as e:
        print("Failed to delete specified account! ", e)
    return credentials

def hide_credentials(config_file_name='pass.json'):
    try:
        with open(config_file_name, 'r') as f:
            file_content=f.read()
            format="plain"
            try:
                file_content=base64.b64decode(file_content.encode()).decode()
                format="base64"
            except:
                pass
            try:
                credentials = json.loads(file_content)
            except:
                print("Error parsing config")
                return
            if format=="base64":
                print("Already Hidden!")
                return
            with open(config_file_name, 'w') as f2:
                f2.write(base64.b64encode(json.dumps(credentials).encode()).decode())
                print("Credentials are hidden now!")
    except Exception as e:
        print("Hiding credentials failed! ", e)

def check_net2_connection(s, verbose=True, print_already=True):
    r=s.get(net2_url.format('status'))
    if r.status_code!=200:
        if verbose:
            print("Not connected!")
        return None
    else:
        soup = BeautifulSoup(r.text, 'html.parser')
        try:
            table_info=soup.find_all('table')[1]
        except:
            table_info=None
        dict_info={}
        if table_info is not None:
            for tr in table_info.find_all('tr'):
                tds=tr.find_all('td')
                dict_info[tds[0].getText().replace(":", "")]=tds[1].getText()
        page_title=soup.title.contents[0]
        if "logout" in page_title:
            if verbose:
                if print_already:
                    print("Already Connected!")
                for info, info_val in dict_info.items():
                    print(f'{info}: {info_val}')
            return dict_info
        else:
            return {}

def login(s, credentials, verbose=True):
    dict_info=check_net2_connection(s, verbose=True)
    if dict_info is None:
        return None
    elif dict_info!={}:
        return "Already Done"
    r2=s.post(net2_url.format('login'), data=credentials)
    if r2.status_code!=200:
        print("Not able to login!")
    else:
        soup2 = BeautifulSoup(r2.text, 'html.parser')
        page_title2=soup2.title.contents[0]
        if 'mikrotik' in page_title2:
            print('Done :)')
            if verbose:
                try:
                    s2=init_requests_session()            
                    check_net2_connection(s2, verbose=True, print_already=False)
                except:
                    pass
        else:
            print("Incorrect password or low balance!")

def check_bw(s, credentials):
    c={'normal_username': credentials['username'], 'normal_password': credentials['password']}
    r_=s.get(bw_url)
    r=s.post(bw_url, data=c)
    if r.status_code!=200:
        print("Not connected!")
    else:
        soup = BeautifulSoup(r.text, 'html.parser')
        # d=soup.find('div', {'id':'legend'})
        script_elements=soup.find_all('script')
        if len(script_elements)>0:
            script_element=script_elements[-1].contents[0]
        else:
            print("Script not found!!")
            return False
        table_elements=soup.find_all('div', {'class': 'table-responsive'})
        user_info={}
        sessions_info=[]
        for table_element in table_elements:
            title=table_element.find("table").find('thead').find("th").getText()
            table_body=table_element.find("table").find('tbody')
            if title=="اطلاعات کاربری":
                for tr in table_body.find_all("tr"):
                    all_trs=tr.find_all("td")
                    key=all_trs[0].getText()
                    val=all_trs[1].getText()
                    if key=="نام کاربری":
                        val=val.replace(" ", '').replace("\t", "").replace("\n", "")
                    user_info[key]=val
            elif title=="زمان لاگین":
                keys=[ "قطع کردن" if ("قطع" in x.getText() and "کردن" in x.getText()) else x.getText() for x in table_element.find("table").find('thead').find_all("th")]
                for tr in table_body.find_all("tr"):
                    session_info={}
                    for key, td in zip(keys, tr.find_all('td')):
                        if key=="قطع کردن":
                            session_info[key]="قطع کردن"
                            # d={}
                            # for inp in td.find_all("input"):
                            #     d[inp.get("name")]=inp.get("value")
                            # # print(d)
                            # r=s.post(bw_url.replace("login", "main"), data=d)
                            # if r.status_code!=200:
                            #     print("Unable to kill!")
                            # else:
                            #     print(r.content)
                        else:
                            session_info[key]=td.getText()
                    disconnect_form = tr.find("form")
                    all_inputs={x.attrs['name']: x.attrs['value'] for x in disconnect_form.find_all("input")}
                    all_inputs["disconnect"]=''
                    session_info["form"]=all_inputs
                    sessions_info.append(session_info)
                    
        username=user_info.get('نام کاربری', None)
        groupclass=user_info.get('گروه کاربری', '').replace(" ","")
        
        remaining_data_raw=re.findall('باقی مانده\', value: [0-9]+\.?[0-9]*', script_element)[0]
        remaining_data=re.split(' ', remaining_data_raw)[-1]
        t=JalaliDate.today()
        if t.day < 10:
            remaining_days=(10-t.day)
        else:
            remaining_days=10+t.days_in_month(t.month, t.year)-t.day
        if remaining_days==0:
            print(f'({username}) You have {remaining_data} GB remaining data from now to 23:59 PM')
        else:
            print(f'({username}) You have {remaining_data} GB remaining data for {remaining_days} days({float(remaining_data)/remaining_days:.2f}  GB per day).')
        print("Details:")
        print(f'''\tUsername: {username}\n\tClass: {groupclass}\n\t''')
        print("Sessions:")
        for i,session_info in enumerate(sessions_info, 1):
            login_time=session_info.get('زمان لاگین', None)
            ip=session_info.get('آی پی', None)
            dict_params=session_info.get('form', None)
            print(f"\t{i}- IP: {ip}, LogInTime: {login_time}, \n\t\t({dict_params})")
        return sessions_info
            

def check_net_sharif_login(s):
    for prefix in ('http://', 'https://'):
        s.get_adapter(prefix).init_poolmanager(
            # those are default values from HTTPAdapter's constructor
            connections=requests.adapters.DEFAULT_POOLSIZE,
            maxsize=requests.adapters.DEFAULT_POOLSIZE,
            # This should be a tuple of (address, port). Port 0 means auto-selection.
            source_address=('172.27.210.8', 0),
        )

    r3=s.get(f'{net_url}/en-us/user/get_info_user/', verify=False, headers=net_headers)
    return len(r3.text)>0

def disconnect_net(s, credentials):
    # net_sharif(s, credentials)
    sessions_info=check_bw(s, credentials)
    for session_info in sessions_info:
            login_time=session_info.get('زمان لاگین', None)
            ip=session_info.get('آی پی', None)
            should_disconnect=True
            if should_disconnect:
                r_dis=s.post(bw_url.replace("login", 'main'), data=session_info['form'])
                print(r_dis)



def net_sharif(s, credentials):
    cookie_file = 'somefile'
    new_login=True
    if os.path.isfile(cookie_file):
        with open(cookie_file, 'rb') as f:
            s.cookies.update(pickle.load(f))
        new_login=False
        if not check_net_sharif_login(s):
            new_login=True
    
    while new_login:
        r=s.get(f'{net_url}/en-us/', headers=net_headers, verify=False)
        if r.status_code!=200:
            print("Not able to connect to net.sharif.edu!")
            return
    
        
        soup = BeautifulSoup(r.text, 'html.parser')
        html_form=soup.find_all('form', {'method': 'post'})[0]
        token = html_form.find_all('input', {'name': 'csrfmiddlewaretoken'})[0]
        captcha_token = html_form.find_all('input', {'name': 'captcha_0'})[0]
        token = token.attrs['value']
        captcha_token = captcha_token.attrs['value']
        image_captha = html_form.find_all('img', {'alt': 'captcha'})[0]
        captcha_image_src=image_captha.attrs['src']

        file_name = 'captcha.png'
        url_image=f'{net_url}/{captcha_image_src}'
        # urllib.request.urlretrieve(url_image, file_name, verify)
        response = s.get(url_image, stream=True, verify=False)
        with open(file_name, 'wb') as out_file:
            shutil.copyfileobj(response.raw, out_file)
        del response
        try:
            img = Image.open(file_name)
            img.show()
        except:
            image_as_text = climage.convert(file_name, width=100)
            print(image_as_text)
        captcha_text=input('Enter Captcha: ')


        c={
            'csrfmiddlewaretoken': token,
            'username': credentials['username'],
            'password': credentials['password'],
            'captcha_0': captcha_token,
            'captcha_1': captcha_text
        }
        r2=s.post(f'{net_url}/en-us/user/login/', data=c, verify=False, headers=net_headers)
        if r2.status_code!=200:
            print("Not able to login!")
            return

        soup2 = BeautifulSoup(r2.text, 'html.parser')
        if check_net_sharif_login(s):
            with open(cookie_file, 'wb') as f:
                pickle.dump(s.cookies, f)
            new_login=False
    
    r3=s.get(f'{net_url}/en-us/user/get_info_user/', verify=False, headers=net_headers)
    users=json.loads(r3.text)
    profiles=[]
    user_id=0
    for userid, user_info in users.items():
        print(f"--------------------------------------------------------------------------\nUser:#{userid}")
        # print(json.dumps(user_info['basic_info'], indent=2))
        # print(json.dumps(user_info['attrs'], indent=2))
        profiles = user_info['internet_onlines']
        user_id=userid
        
    print("--------------------------------------------------------------------------")
    for profile in profiles:
        ras=profile[0]
        u_id=profile[2]
        date_time=profile[3]
        ip=profile[4]
        url=f'{net_url}/en-us/user/disconnect/?user_id={user_id}&ras={ras}&ip={ip}&u_id={u_id}'
        s.get(url, verify=False, headers=net_headers)

def logout(s, force = False):
    dict_info=check_net2_connection(s, verbose=False)
    if dict_info is None or dict_info=={}:
        print("Already Logged out!")
        if not force:
            return
    r=s.get(net2_url.format('logout'))
    if r.status_code!=200:
        print("Not connected!")
    else:
            print("Successfully disconnected :)")

def find_best_interface(interfaces_dict):
    s=init_requests_session()
    try:
        r=s.get(net2_url.format('status'), timeout=2)
        if r.status_code==200 or r.status_code==302:
            return ("direct", "0.0.0.0")
    except Exception as e:
        for i_name, i_ip in interfaces_dict.items():
            if i_name=="lo" or i_name.startswith('docker') or i_ip is None:
                continue
            for prefix in ('http://', 'https://'):
                s.get_adapter(prefix).init_poolmanager(
                    # those are default values from HTTPAdapter's constructor
                    connections=requests.adapters.DEFAULT_POOLSIZE,
                    maxsize=requests.adapters.DEFAULT_POOLSIZE,
                    # This should be a tuple of (address, port). Port 0 means auto-selection.
                    source_address=(i_ip, 0),
                )
            try:
                r=s.get(net2_url.format('status'), timeout=1)
                if r.status_code==200 or r.status_code==302:
                    return i_name, i_ip
            except Exception as e:
                # print(e.args[0])
                continue
            return ("default", "0.0.0.0")

        
def main():
    credentials=get_config_credentials()
    account_list=list(credentials.keys())

    # interfaces_dict={iname[1]: get_ip_address(iname[1].encode()) for iname in socket.if_nameindex()}
    # adapters = ifaddr.get_adapters()

    # for adapter in adapters:
    #     # print("IPs of network adapter " + adapter.nice_name)
    #     ips =[ip for ip in adapter.ips if ip.is_IPv4]
    #     if len(ips)>0:
    #         print(f'{ips[0].nice_name}:{ips[0].ip}')

    # interfaces_dict={adapter.ips[0].nice_name: adapter.ips[0].ip for adapter in adapters if len(adapter.ips)>0}
    # interfaces_dict={x:netifaces.ifaddresses(x).get(netifaces.AF_INET) for adapter in adapters}
    # interfaces_dict={k: v[0]['addr'] for k, v in interfaces_dict.items() if v is not None}
    
    # default_interface=ifcfg.default_interface()["device"]
    
    interfaces_dict={name:interface['inet4'] 
        for name, interface in ifcfg.interfaces().items() if interface['inet4']is not None
    }
    interfaces_dict={ name: (interface[0] if len(interface)>0 else None) if  isinstance(interface, list) else interface
        for name, interface in interfaces_dict.items()
    }

    interfaces_to_choose=list(interfaces_dict.keys())
    interfaces_to_choose.insert(0,"Auto")
    interfaces_to_choose.insert(1, "Smart")
    msg="Sharif Net2 Script"
    parser = argparse.ArgumentParser(description = msg)
    parser.add_argument("-d", "--Disconnect", help = "Disconnect from net2", action = "store_true")
    parser.add_argument("-C", "--Connect", help = "Connect to your net2 account[Activated by Default]", default=True, action = "store_true")
    parser.add_argument("-c", "--Check", help = "Check Account Balance", action = "store_true")
    parser.add_argument("-f", "--ForceLogin", action = "store_true", help = "Force Login(Logout from all other devices and login this device")
    parser.add_argument("-x", "--Disconnect-All",action = "store_true" , help = "Disconnect from All Devices")
    parser.add_argument("-i", "--Interface", help = "Interface Name[Default Smart]", default='Smart', choices=interfaces_to_choose)
    parser.add_argument("-v", "--Verbose", help = "Verbose", action = "store_true")
    parser.add_argument("-a", "--Account", help = "Select Account", default=next(iter(credentials)))
    parser.add_argument("-A", "--Add-New-Account", help = "Add new Account", action = "store_true")
    parser.add_argument("-D", "--Delete-Account", help = "Delete Specified Account", default= "_", choices=account_list)
    parser.add_argument("-l", "--List-Accounts", help = "List Accounts", action = "store_true")
    parser.add_argument("-H", "--Hide-Credentials", help = "Hide Credentials", action = "store_true")
    
    args= parser.parse_args()
    
    interface_ip = ''
    if args.Interface=="Smart":
        try:
            name, interface_ip = find_best_interface(interfaces_dict)
        except:
            print("Unable to Find best interface!")
            sys.exit(-1)
        if args.Verbose:
            print(f"Best Interface: {name}({interface_ip})")
    elif args.Interface!="Auto":
        interface_ip=interfaces_dict[args.Interface]

    s=init_requests_session(interface_ip)
    
    # credentials=credentials[args.Account]
    account_match=list(credentials.keys())
    scores=[(account, fuzz.ratio(args.Account, account)) for account in account_match]
    scores.sort(key=lambda x: x[1], reverse=True)
    sorted_credentials=[name[0] for name in scores]
    if args.Verbose:
        print(f"Using {sorted_credentials[0]} account")
    credentials=credentials[sorted_credentials[0]]
    if args.Hide_Credentials:
        hide_credentials()
        return
    if args.List_Accounts:
        for ac in sorted_credentials:
            print(ac)
    elif args.Add_New_Account:
        append_new_account()
    elif args.Delete_Account!="_":
        delete_account(args.Delete_Account)
    elif args.Disconnect:
        args.Connect=False
        logout(s, force= args.ForceLogin)
    elif args.Check:
        check_bw(s,credentials)
    elif args.ForceLogin:
        disconnect_net(s,credentials)
        login(s,credentials, verbose=args.Verbose)
    elif args.Disconnect_All:
        disconnect_net(s,credentials)
    elif args.Connect:
        login(s,credentials, verbose=args.Verbose)
    else:
        parser.print_help()
        time.sleep(1)

if __name__ == '__main__':
    main()
