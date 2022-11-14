
from bs4 import BeautifulSoup
import requests
import json
import os
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


net2_url='https://net2.sharif.edu/{}'
bw_url='https://bw.ictc.sharif.edu/login'
net_headers = {
    'Referer': 'https://net.sharif.edu/',
    'Host': 'net.sharif.edu',
    'Accept-Language' : 'en-US,en;q=0.9,fa;q=0.8',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36',
    'X-Requested-With':'XMLHttpRequest'
}

_orig_create_connection = connection.create_connection

def your_dns_resolver(host):
    if host == 'net2.sharif.edu':
        return '172.17.1.214'
    try:
        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = [
                '81.31.160.34', # NOTE: NS1 sharif
                '81.31.160.35', # NOTE: NS2 sharif
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
    hostname = your_dns_resolver(host)

    return _orig_create_connection((hostname, port), *args, **kwargs)

def init_requests_session():
    connection.create_connection = patched_create_connection

    # Suppress only the single warning from urllib3 needed.
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    s=requests.Session()
    s.verify=False
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

def get_config_credentials(config_file_name='pass.json'):
    go_to_app_dir(config_file_name)
    try:
        with open(config_file_name) as f:
            file_content=f.read()
            credentials = json.loads(file_content)
    except FileNotFoundError:
        print('Credentials file not found. Please enter your username:')
        username = input()
        print('Please enter your password:')
        password = input()
        credentials = {'username': username, 'password': password}
        with open(config_file_name, 'w') as f:
            json.dump(credentials, f)
    return credentials

def login(credentials):
    r=requests.get(net2_url.format('status'))
    if r.status_code!=200:
        print("Not connected!")
    else:
        soup = BeautifulSoup(r.text, 'html.parser')
        page_title=soup.title.contents[0]
        if page_title=="logout":
            print("Already Connected!")
        else:
            r2=requests.post(net2_url.format('login'), data=credentials)
            if r2.status_code!=200:
                print("Not able to login!")
            else:
                soup2 = BeautifulSoup(r2.text, 'html.parser')
                page_title2=soup2.title.contents[0]
                if 'mikrotik' in page_title2:
                    print('Done :)')
                else:
                    print("Incorrect password")

def check_bw(credentials):
    c={'normal_username': credentials['username'], 'normal_password': credentials['password']}
    r=requests.post(bw_url, data=c)
    if r.status_code!=200:
        print("Not connected!")
    else:
        soup = BeautifulSoup(r.text, 'html.parser')
        # d=soup.find('div', {'id':'legend'})
        script_element=soup.find_all('script')[-1].contents[0]
        remaining_data_raw=re.findall('باقی مانده\', value: [0-9]+\.[0-9]*', script_element)[0]
        remaining_data=re.split(' ', remaining_data_raw)[-1]
        t=JalaliDate.today()
        if t.day <= 10:
            remaining_days=(10-t.day)
        else:
            remaining_days=10+t.days_in_month(t.month, t.year)-t.day

        print(f'You have {remaining_data} GB remaining data for {remaining_days} days({float(remaining_data)/remaining_days:.2f}  GB per day).')

def check_net_sharif_login(s):
    r3=s.get('https://net.sharif.edu/en-us/user/get_info_user/', verify=False, headers=net_headers)
    return len(r3.text)>0

def net_sharif(credentials):
    s = requests.Session()
    cookie_file = 'somefile'
    new_login=True
    if os.path.isfile(cookie_file):
        with open(cookie_file, 'rb') as f:
            s.cookies.update(pickle.load(f))
        new_login=False
        if not check_net_sharif_login(s):
            new_login=True
    
    while new_login:
        r=s.get('https://net.sharif.edu/en-us/', headers=net_headers, verify=False)
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
        url_image=f'https://net.sharif.edu{captcha_image_src}'
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
        r2=s.post('https://net.sharif.edu/en-us/user/login/', data=c, verify=False, headers=net_headers)
        if r2.status_code!=200:
            print("Not able to login!")
            return

        soup2 = BeautifulSoup(r2.text, 'html.parser')
        if check_net_sharif_login(s):
            with open(cookie_file, 'wb') as f:
                pickle.dump(s.cookies, f)
            new_login=False
    
    r3=s.get('https://net.sharif.edu/en-us/user/get_info_user/', verify=False, headers=net_headers)
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
        url=f'https://net.sharif.edu/en-us/user/disconnect/?user_id={user_id}&ras={ras}&ip={ip}&u_id={u_id}'
        s.get(url, verify=False, headers=net_headers)

def logout():
    r=requests.get(net2_url.format('logout'))
    if r.status_code!=200:
        print("Not connected!")
    else:
        r2=requests.get(net2_url.format('logout'))
        if r2.status_code!=200:
            print("Not able to logout!")
        else:
            print("Successfully disconnected :)")
def help():
    print('\th\tHelp\n\tf\tForceLogin\n\tc\tCheck Account\n\td\tDisconnect(Logout)\n\tx\tDisconnect All Devices')

def main():
    init_requests_session()
    credentials=get_config_credentials()
    msg="sharif net2 script"
    parser = argparse.ArgumentParser(description = msg)
    parser.add_argument("-d", "--Disconnect", help = "Disconnect from net2", action = "store_true")
    parser.add_argument("-C", "--Connect", help = "Connect to your net2 account[Activated by Default]", default=True, action = "store_true")
    parser.add_argument("-c", "--Check", help = "Check Account Balance", action = "store_true")
    parser.add_argument("-f", "--ForceLogin", action = "store_true", help = "Force Login(Logout from all other devices and login this device")
    parser.add_argument("-x", "--Disconnect-All",action = "store_true" , help = "Disconnect from All Devices")
    
    args= parser.parse_args()
    if args.Disconnect:
        args.Connect=False
        logout()
    elif args.Check:
        check_bw(credentials)
    elif args.ForceLogin:
        net_sharif(credentials)
        login(credentials)
    elif args.Disconnect_All:
        net_sharif(credentials)
    elif args.Connect:
        login(credentials)
    else:
        help()
        time.sleep(1)

if __name__ == '__main__':
    main()
