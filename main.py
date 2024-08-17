import requests,threading,webbrowser
from time import sleep
import random
from bs4 import BeautifulSoup
class Mail:
    def __init__(self, email=None):
        self.url = 'https://api.guerrillamail.com/ajax.php'
        self.email = email
        self.token = None
    def Access(self, email):
        self.email = email
    
    def Random_email(self):
        letters = 'abcdefghijklmnopqrstuvwxyz'
        numbers = '0123456789'
        self.email = ''.join(random.choices(letters, k=8))+''.join(random.choices(letters+numbers, k=5))
        self.email += '@guerrillamailblock.com'
        return self.email
    
    def Get_token(self):
        data = {
            'f': 'set_email_user', # funcation
            'email_user': self.email,
            'lang': 'en',
            'site_id': 2
        }
        res = requests.post(self.url, data=data)
        self.token = res.json()['sid_token']

    def Inbox(self):
        if not self.email: return []
        self.Get_token()
        data = {
            'f': 'check_email',
            'seq': self.token
        }
        headers = {
            'Cookie': f'PHPSESSID={self.token};'
        }
        res = requests.post(self.url, data=data, headers=headers)
        return res.json()['list']
    
    def Inbox_HTML(self, email_id):
        if not self.email: return []
        self.Get_token()
        data = {
            'f': 'fetch_email',
            'email_id': email_id
        }
        headers = {
            'Cookie': f'PHPSESSID={self.token};'
        }
        res = requests.post(self.url, data=data, headers=headers)

        return res.json()['mail_body']
    
    def GetInstagramSignupCode(self):
        if not self.email: return None
        for msg in self.Inbox():
            if 'mail.instagram.com' in msg['mail_from'] and 'Instagram code' in msg['mail_subject']:
                return msg['mail_subject'].split()[0]
        return None

    def GetInstagramChallengeCode(self):
        try:
            res = ''
            for msg in self.Inbox():
                if msg['mail_from'] == 'security@mail.instagram.com' and msg['mail_subject']=='Verify your account':
                    res = self.Inbox_HTML(msg['mail_id'])
            soup = BeautifulSoup(res, 'html.parser')

            confirmation_code = soup.find('font').text.strip()
            return confirmation_code
        
        except:
            return None
class Insta():
	def __init__(self, file):
		self.adet = 600
		self.user = None
		self.id = None
		self.code = None
		self.delayTime = 0
		self.login_errors = 0
		self.file = file
		self.headers = {
			"accept": "application/json, text/javascript, */*; q=0.01",
			"accept-language": "en-US,en;q=0.9",
			"content-type": "application/x-www-form-urlencoded; charset=UTF-8",
			"priority": "u=1, i",
			"sec-ch-ua": "\"Chromium\";v=\"124\", \"Microsoft Edge\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
			"sec-ch-ua-mobile": "?0",
			"sec-ch-ua-platform": "\"Windows\"",
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
			"x-requested-with": "XMLHttpRequest"
		}
		self.cookies = {

		}
		self.GlobalData = {
			'login': 'login',
			'login-data': {
				'username': 'username',
				'password': 'password'
			},
			'send-follower': 'tools/send-follower',
			'send-follower-data': {
				'adet': 'adet',
				'user-id': 'userID',
				'username': 'userName'
			}
		}
		self.Websites = {
			'medyahizmeti.com': {
				'login': 'member'
			},
			'takipcikrali.com': {},
			'takipcimx.com': {},
			'takipciking.net': {},
			'takipfun.net': {},
			'followersize.net': {},
			'takipciking.com': {
				'login': 'member'
			},
			'instamoda.org': {},
			'takipcitime.com': {},
			'followersize.com': {
				'login': 'member'
			},
			'birtakipci.com': {
				'login': 'member'
			},
			'bigtakip.com': {
				'login': 'member'
			},
			'takipcizen.com': {},
			'bigtakip.net': {},
			'anatakip.com': {},
			'takip88.com': {},
			
			'takipcimx.net': {},
			'bayitakipci.com': {
				'login': 'memberlogin'
			},
			'takipzan.com': {},
			'fastfollow.in': {
				'login': 'member'
			},
			'hepsitakipci.com': {
				'login': 'member'
			},
			
			
			'takipcigir.com': {},
			'takipcibase.com': {},

		}
	def Get_User(self):
		while not self.id:
			try:
				self.user = "__tamim_sk8__"
				he = {
					'user-agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
					'x-ig-app-id': '936619743392459',
				}
				urlg = f'https://i.instagram.com/api/v1/users/web_profile_info/?username={self.user}'
				#print(urlg)
				re =requests.get(urlg,headers=he).json()
				self.id = re["data"]["user"]["id"]
				if self.id:
					print("[~] usr : "+str(self.user))
					print("[~] Your ID : "+str(self.id))
				else:
					print("[!] Wrong User. Try Again !")
			except KeyboardInterrupt:
				exit(0)
			# except:
			# 	print("[!] Wrong User. Try Again !")
	
	def delay(self):
		for i in range(self.delayTime, 0, -1):
			print(' Sleeping', i, end='                \r')
			sleep(1)
	def Login_Request_Data(self, website, username, password):
		try:    _page=self.Websites[website]['login']
		except: _page=self.GlobalData['login']
		url = f'https://{website}/{_page}?'
		try:    _username = self.Websites[website]['login-data']['username']
		except: _username = self.GlobalData['login-data']['username']
		try:    _password = self.Websites[website]['login-data']['password']
		except: _password = self.GlobalData['login-data']['password']
		data = {
			_username: username,
			_password: password,
		}
		return url, data
	
	def Send_Followers_Request_Data(self, website, username, password):
		try:    _page = self.Websites[website]['send-follower']
		except: _page = self.GlobalData['send-follower']

		url = f'https://{website}/{_page}/{self.id}?formType=send'
		try:    _adet=self.Websites[website]['send-follower-data']['adet']
		except: _adet = self.GlobalData['send-follower-data']['adet']
		try:    _user=self.Websites[website]['send-follower-data']['username']
		except: _user = self.GlobalData['send-follower-data']['username']
		try:    _id=self.Websites[website]['send-follower-data']['user-id']
		except: _id = self.GlobalData['send-follower-data']['user-id']

		data = {
			_adet: self.adet,
			_id: self.id,
			_user: self.user
		}
		return url, data
	def get_tokens(self, website):
		url = f"https://{website}"
		
		response = requests.get(url, headers=self.headers)
		self.cookies = {}
		for cookie in response.cookies:
			self.cookies[cookie.name] = cookie.value
		
		# print(self.cookies)
		
	def Cookies(self, res):
		cookies=""
		for cookie in res.cookies:
			cookies+=cookie.name+'='+cookie.value+';'
		return cookies[:-1]


	def Login(self, website, username, password):
		print(f"[*] {website} : Logging in ...", end='\r')

		url, data = self.Login_Request_Data(website, username, password)

		
		res = requests.post(url,headers=self.headers,data=data, cookies=self.cookies)
		# print(res.text)
		for cookie in res.cookies:
			self.cookies[cookie.name] = cookie.value
		if res.json()["status"]=="success":
			print(f"[~] {website} : Done Login ", ' '*20)
			return self.Cookies(res)
		elif res.json()["status"] == '3':
			print("Code Required !")
			self.code = 'Require'
			self.data = res.json()['allData']['step_data']
			return self.Cookies(res)
		elif res.json()['status'] == '0':
			self.login_errors += 1
			print(f"[~] {website} : {username} ", ' '*20)
			return False
			# print(f"[~] {website} : {username} ", ' '*20)
		print()
		return False
	
	def Send_Followers(self, website, username, password):
		cookie = self.Login(website, username, password)
		if self.code == 'Require':
			self.cookie = cookie
			try:
				cookie = self.send_code(self.data, website, username, password)
			except:
				print("unExpected Error !")
			self.code = None
		if not cookie:
			return
		
		url, data = self.Send_Followers_Request_Data(website, username, password)

		try:
			res = requests.post(url,headers=self.headers,data=data, cookies=self.cookies)
			# print(res.test)
			if res.json()['status']=="error":
				print(f"[×] {website} : Error Send Followers ❌", ' '*20)
			else:
				print(f"[√] {website} : Done Send Followers ✅", ' '*20)
		except:
			print(f"[×] {website} : Error Send Followers ❌", ' '*20)
		self.delay()
	
	def Start_Send_Follower(self):
		print("Accounts :", len(open(self.file).readlines()))
		print("Websites :", len(self.Websites.keys()))
		for i in open(self.file).readlines():
			if not i.strip(): continue
			username, password = i.strip().split(':')
			if not username or not password:
				continue
			self.login_errors = 0
			for website in self.Websites.keys():
				# print(username, password, i)
				self.get_tokens(website)
				
				self.Send_Followers(website, username, password)
			if self.login_errors >= len(self.Websites.keys())-7:
				print("🗑 Remove Account 🗑")
				self.remove_account(username, password)

	def send_code(self, Data, website, username, password):
		Data['status'] = 'fail'
		Data['message'] = 'code_verification'
		url = f"https://{website}/ajax/kod-gonder"
		
		data = {
            "step_name": "select_verify_method",
            "step_data[choice]": Data['choice'],
            "step_data[fb_access_token]": Data['fb_access_token'],
            "step_data[big_blue_token]": Data['big_blue_token'],
            "step_data[google_oauth_token]": Data['google_oauth_token'],
            "step_data[vetted_device]": Data['vetted_device'],
            "step_data[email]": Data['email'],#"m*******7@g*****.com",
            "step_data[show_selfie_captcha]": Data['show_selfie_captcha'],
            "step_data[use_company_branding]": Data['use_company_branding'],
            "status": Data['status'],
            "message": Data['message'],
            "username": username,
            "password": password,
            "choice": "1"
        }
		response = requests.post(url, headers=self.headers, data=data, cookies=self.cookies)
		# print(response.text)
		if response.json()['status'] == 'ok':
			print("Done Send Code !")
			return self.submit_code(Data, website, username, password)
		
		return False
	
	def get_code(self, email):
		print("Getting Code !")
		mail = Mail(email)
		for _ in range(10):
			code = mail.GetInstagramChallengeCode()
			if code:
				break
			sleep(1)
		if code:
			print("Code : ",code)
		else :
			print("Faild To Get Code !")
		return code
	
	def submit_code(self, data,website, username, password):
		code = self.get_code(username)
		if not code: return code
		url = f"https://{website}/ajax/kod-onayla"


		data = {
			"step_name": "select_verify_method",
			"step_data[choice]": "1",
			"step_data[fb_access_token]": "None",
			"step_data[big_blue_token]": "None",
			"step_data[google_oauth_token]": "true",
			"step_data[vetted_device]": "None",
			"step_data[email]": data['email'],
			"step_data[show_selfie_captcha]": "true",
			"step_data[delta_enable_new_ui]": "True",
			"step_data[use_company_branding]": "true",
			"status": "fail",
			"message": "code_verification",
			"username": username,
			"password": password,
			"choice": "1",
			"code": code
		}

		response = requests.post(url, headers=self.headers, data=data, cookies=self.cookies)

		if response.status_code == 200:
			print(" Print done submit code ")
			return self.Login(website, username, password)
		return False
	
	def remove_account(self, username, password):
		data = ''
		with open(self.file) as f: data=f.read()
		with open(self.file, 'w') as f:
			f.write(data.replace(f'{username}:{password}', '').replace('\n\n', '\n'))
		print("Done Account Removed !")

			
x=Insta('acc.txt')


x.Get_User()

while True:
    x.Start_Send_Follower()

# 
# mail = Mail('sumfseqdntlwm')
# print(mail.GetInstagramChallengeCode())
# canlitakipci.com --> website is down
# instavevo.com    --> website is down
# instahile.co     --> diffr
# beyaztakip.com   --> diffr
# takipcitime.net  --> cloud flare
# takipcimax.com   --> cloud flare
