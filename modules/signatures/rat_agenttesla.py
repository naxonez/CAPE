import re
from lib.cuckoo.common.abstracts import Signature

matches = (
	"AppData\Local\VirtualStore\Program Files\Foxmail\mail",
        "AppData\Local\VirtualStore\Program Files (x86)\Foxmail\mail",
        "AppData\Roaming\Opera Mail\Opera Mail\wand.dat",
        "AppData\Roaming\Pocomail\accounts.ini",
        "AppData\Roaming\The Bat!",
        "C:\mail",
        "AppData\Roaming\Opera Mail\Opera Mail\wand.dat",
        "AppData\Roaming\Pocomail\accounts.ini",
        "AppData\Roaming\Claws-mail\clawsrc",
        "AppData\Roaming\Trillian\users\global\accounts.dat",
        "AppData\Roaming\Psi\profiles",
        "AppData\Roaming\Psi+\profiles",
        "AppData\Roaming\Ipswitch\WS_FTP\Sites\ws_ftp.ini",
        "AppData\Roaming\FlashFXP\3quick.dat",
        "C:\cftp\Ftplist.txt",
        "AppData\Roaming\FTPGetter\servers.xml",
        "jDownloader\config\database.script",
        "AppData\Local\Google\Chrome\User Data",
        "AppData\Local\Yandex\YandexBrowser\User Data",
        "AppData\Local\360Chrome\Chrome\User Data",
        "AppData\Local\Comodo\Dragon\User Data",
        "AppData\Local\MapleStudio\ChromePlus\User Data",
        "AppData\Local\Chromium\User Data",
        "AppData\Local\Torch\User Data",
        "AppData\Local\BraveSoftware\Brave-Browser\User Data",
        "AppData\Local\Iridium\User Data",
        "AppData\Local\7Star\7Star\User Data",
        "AppData\Local\Amigo\User Data",
        "AppData\Local\CentBrowser\User Data",
        "AppData\Local\Chedot\User Data",
        "AppData\Local\CocCoc\Browser\User Data",
        "AppData\Local\Elements Browser\User Data",
        "AppData\Local\Epic Privacy Browser\User Data",
        "AppData\Local\Kometa\User Data",
        "AppData\Local\Orbitum\User Data",
        "AppData\Local\Sputnik\Sputnik\User Data",
        "AppData\Local\uCozMedia\Uran\User Data ",
        "AppData\Local\Vivaldi\User Data",
        "AppData\Roaming\Fenrir Inc\Sleipnir5\setting\modules\ChromiumViewer",
        "AppData\Local\CatalinaGroup\Citrio\User Data",
        "AppData\Local\Coowon\Coowon\User Data",
        "AppData\Local\liebao\User Data",
        "AppData\Local\QIP Surf\User Data",
        "AppData\Local\Tencent\QQBrowser\User Data",
        "AppData\Local\UCBrowser",
        "AppData\Roaming\Mozilla\Firefox"
)

class agent_tesla(Signature):
	name = "Agent Tesla Behavior"
	description = "Detects Agent Tesla Behavior"
	weight = 3
	severity = 3
	categories = ["RAT"]
	families = ["agent_tesla"]
	authors = ["@NaxoneZ"]
	minimum = "1.2"
	evented = True
	samples = {
	"Agent_Tesla":
		{
			"1": "97ad2cef166527d3d9f808bc7fc0da8e73f4fa6a3405c785f468ded0d69f49d3", #variant1
			"2": "2274f0b2e9370ac7e7e7777c34766c09b09ef528fbbf6a6b04e1291e69ff6bd6", #variant1
			"3": "ba1410576f819a2b743d15f3861a62366c246506f5abf0df67982f8224e9c2b9", #variant2
		}
	}

	def __init__(self, *args, **kwargs):
		Signature.__init__(self, *args, **kwargs)
		self.badness_files = 0
		self.badness_urls = 0
		self.badness_smtp = 0

	filter_apinames = set(["GetAddrInfoW","NtQueryFullAttributesFile", "send"])

	def on_call(self, call, process):
		#Call to checkip.amazonws.com
		if call["api"] == "GetAddrInfoW":
			node = self.get_argument(call,"NodeName")

			if re.findall("checkip.amazonaws.com|checkip.dyndns.org",node):
				self.badness_urls += 1

		if call["api"] == "send":
			node = self.get_argument(call,"buffer")

			if re.findall("checkip.amazonaws.com|checkip.dyndns.org",node):
				self.badness_urls += 1

			if re.findall("EHLO|STARTTLS",node):
				self.badness_smtp += 1


		if call["api"] == "NtQueryFullAttributesFile":
			node = self.get_argument(call,"FileName")

			for i in matches:
				if i in node:
					self.badness_files += 1

	def on_complete(self):
		if self.badness_files > 10 and self.badness_urls > 0 or self.badness_files > 1 and self.badness_urls > 10 and self.badness_smtp > 3:
			return True
		else:
			return False
