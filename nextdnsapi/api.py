import requests
import json
from json import JSONDecodeError
import os
from pathlib import Path

nativetracking = ["sonos", "xiaomi", "apple", "windows", "huawei", "samsung", "alexa", "roku"]

blocksites = [
    "tiktok",
    "tinder",
    "facebook",
    "snapchat",
    "instagram",
    "fortnite",
    "messenger",
    "leagueoflegends",
    "9gag",
    "tumblr",
    "vk",
    "roblox",
    "twitch",
    "minecraft",
    "pinterest",
    "discord",
    "twitter",
    "dailymotion",
    "whatsapp",
    "steam",
    "youtube",
    "hulu",
    "reddit",
    "blizzard",
    "netflix",
    "imgur",
    "vimeo",
    "disney+",
    "telegram",
    "skype",
    "ebay",
    "spotify",
    "amazon",
    "zoom",
    "primevideo",
    "xboxlive",
    "signal"]

headers = {
    """Accept""": """application/json, text/plain, */*""",
    """Accept-Language""": """en-US,en;q=0.5""",
    """Content-Type""": """application/json""",
    """Origin""": """https://my.nextdns.io""",
    """DNT""": """1""",
    """Connection""": """keep-alive""",
    """Referer""": """https://my.nextdns.io/""",
    """Sec-Fetch-Dest""": """empty""",
    """Sec-Fetch-Mode""": """cors""",
    """Sec-Fetch-Site""": """same-site""",
    """Sec-GPC""": """1""",
    """TE""": """trailers""",
}


class NoCredentials(Exception):
    def __init__(self, message="No credentials in account.login() function. Login using account.login(email,password)"):
        self.message = message
        super().__init__(self.message)


class NewAccount(Exception):
    def __init__(self,
                 message="No credentials in account.signup() function. Login using account.signup(email,password)"):
        self.message = message
        super().__init__(self.message)


class FailedCredentials(Exception):
    def __init__(self, error):
        self.error = error
        if error == """{"errors":{"code":"invalid"}}""":
            self.message = "2FA code invalid. Please check credentials, login using account.login(email,password) and enter the correct 2FA code"
        else:
            self.message = f"Credentials in account.login() function failed. Please check credentials and login using account.login(email,password)\nError: {error}"
        super().__init__(self.message)


class OptionUnavailable(Exception):
    def __init__(self, allowed, message="Supplied option is unavailable, probably cause it does not exist"):
        self.allowed = allowed
        self.message = message
        super().__init__(self.message)


class ConfigNotFound(Exception):
    def __init__(self, config):
        self.config = config
        self.message = f"Config {config} cannot be found, probably cause it does not exist"
        super().__init__(self.message)


class account:
    def signup(self, password: str = None):
        if self is None or password is None:
            raise NewAccount
        json = {"email": f"{self}", "password": f"{password}"}
        signup = requests.post('https://api.nextdns.io/accounts/@login', headers=headers, json=json)
        return "OK" if signup.text == "OK" else signup.text

    def login(self, password: str = None, otp: str = None):
        if self is None or password is None:
            raise NoCredentials
        success = False
        json = {"email": f"{self}", "password": f"{password}"}
        while not success:
            login = requests.post('https://api.nextdns.io/accounts/@login', headers=headers, json=json)
            if login.text == "OK":
                success = 1
            elif login.text == """{"requiresCode":true}""":
                code = otp or input("""Please enter 2FA Code: """)
                json = {"email": f"{self}", "password": f"{password}", "code": f"{code}"}
                login = requests.post('https://api.nextdns.io/accounts/@login', headers=headers, json=json)
            else:
                raise FailedCredentials(login.text)
        c = login.cookies.get_dict()
        c = c['pst']
        headers['Cookie'] = f'pst={c}'
        return headers

    def list(self):
        configs = requests.get(
            "https://api.nextdns.io/accounts/@me?withConfigurations=true",
            headers=self,
        )
        configs = configs.json()
        return configs['configurations']

    def month(self):
        month = requests.get("https://api.nextdns.io/accounts/@me/usage", headers=self)
        month = month.json()
        return month


class settings:
    def listsettings(self, header):
        list = requests.get(
            f"https://api.nextdns.io/profiles/{self}/settings", headers=header
        )
        if list.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        list = list.json()
        return list

    def setup(self, header):
        setup = requests.get(
            f"https://api.nextdns.io/profiles/{self}/setup", headers=header
        )
        print(setup.text)
        if setup.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        setup = setup.json()
        return setup

    def downloadlogs(self, header):
        downloads_path = str(Path.home() / "Downloads")
        fname = f'{self}.csv'
        file_path = os.path.join(downloads_path, fname)
        file = open(file_path, "wb")
        r = requests.get(
            f"https://api.nextdns.io/profiles/{self}/logs/download/",
            headers=header,
            stream=True,
        )
        for chunk in r.iter_content(chunk_size=1024):
            file.write(chunk)
        return fname

    def clearlogs(self, header):
        logs = requests.delete(
            f"https://api.nextdns.io/profiles/{self}/logs", headers=header
        )
        if logs.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        else:
            return logs.text

    def rename(self, config, header):
        nname = {"name": self}
        rename = requests.patch(f"https://api.nextdns.io/profiles/{config}", headers=header, json=nname)
        if rename.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return f"Config renamed to {self}"

    def delete(self, header):
        dconfig = requests.delete(
            f"https://api.nextdns.io/profiles/{self}", headers=header
        )
        if dconfig.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        else:
            return f"Config {self} deleted"

    def logclientips(self, config, header):
        self = self != True
        logcips = {"ip": self}
        logcips = requests.patch(f"https://api.nextdns.io/profiles/{config}/settings/logs/drop", headers=header,
                                 json=logcips)
        if logcips.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return logcips.text

    def logdomains(self, config, header):
        self = self != True
        logdom = {"domain": self}
        logdom = requests.patch(f"https://api.nextdns.io/profiles/{config}/settings/logs/drop", headers=header,
                                json=logdom)
        if logdom.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return logdom.text

    def blockpage(self, config, header):
        bp = {"enabled": self}
        bp = requests.patch(f"https://api.nextdns.io/profiles/{config}/settings/blockPage", headers=header, json=bp)
        if bp.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return bp.text

    def updatelinkedip(self, header):
        r = settings.setup(self, header)
        updatetoken = r["data"]["linkedIp"]["updateToken"]
        updateip = requests.get(f"https://link-ip.nextdns.io/{self}/{updatetoken}")
        print(updateip.text)
        return updateip.text


class security:
    def list(self, header):
        settings = requests.get(
            f"https://api.nextdns.io/profiles/{self}/security", headers=header
        )
        if settings.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        settings = settings.json()
        return settings

    def threatintelligencefeeds(self, config, header):
        setting = {"threatIntelligenceFeeds": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def aidetection(self, config, header):
        setting = {"aiThreatDetection": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def safebrowsing(self, config, header):
        setting = {"googleSafeBrowsing": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def cryptojacking(self, config, header):
        setting = {"cryptojacking": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def dnsrebinding(self, config, header):
        setting = {"dnsRebinding": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def homograph(self, config, header):
        setting = {"idnHomographs": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def typosquatting(self, config, header):
        setting = {"typosquatting": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def dga(self, config, header):
        setting = {"dga": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def newdomains(self, config, header):
        setting = {"nrd": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def dyndns(self, config, header):
        setting = {"ddns": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def parked(self, config, header):
        setting = {"parking": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def csam(self, config, header):
        setting = {"csam": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/security", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def addtld(self, config, header):
        data = {"id": self}
        put = requests.post(f"https://api.nextdns.io/profiles/{config}/security/tlds",
                            headers=header, json=data)
        if put.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return put.text

    def removetld(self, config, header):
        remove = requests.delete(
            f"https://api.nextdns.io/profiles/{config}/security/tlds/{self}",
            headers=header,
        )
        if remove.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return remove.text


class privacy:
    def list(self, header):
        settings = requests.get(
            f"https://api.nextdns.io/profiles/{self}/privacy", headers=header
        )
        if settings.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        settings = settings.json()
        return settings

    def blockdisguised(self, config, header):
        setting = {"disguisedTrackers": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/privacy", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def blockaffiliate(self, config, header):
        setting = {"allowAffiliate": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/privacy", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def blocknative(self, config, header):
        if self in nativetracking:
            data = {"id": self}
            put = requests.post(f"https://api.nextdns.io/profiles/{config}/privacy/natives/", headers=header,
                                json=data)
            if put.text.__contains__("notFound"):
                raise ConfigNotFound(config)
            else:
                return "OK"
        else:
            print("Allowed: ", nativetracking)
            return f"{self} is no valid parameter!"

    def unblocknative(self, config, header):
        if self in nativetracking:
            delete = requests.delete(
                f"https://api.nextdns.io/profiles/{config}/privacy/natives/{self}",
                headers=header,
            )
            if delete.text.__contains__("notFound"):
                raise ConfigNotFound(config)
            else:
                return "OK"
        else:
            print("Allowed: ", nativetracking)
            return f"{self} is no valid parameter!"


class parental:
    def list(self, header):
        settings = requests.get(
            f"https://api.nextdns.io/profiles/{self}/parentalcontrol",
            headers=header,
        )
        if settings.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        settings = settings.json()
        return settings

    def porn(self, config, header):
        if self:
            data = {"id": "porn", "active": self}
            setting = requests.post(f"https://api.nextdns.io/profiles/{config}/parentalcontrol/categories",
                                    headers=header, json=data)
        else:
            setting = requests.delete(f"https://api.nextdns.io/profiles/{config}/parentalcontrol/categories/porn",
                                      headers=header)

        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def gambling(self, config, header):
        if self:
            data = {"id": "gambling", "active": self}
            setting = requests.post(f"https://api.nextdns.io/profiles/{config}/parentalcontrol/categories",
                                    headers=header, json=data)
        else:
            setting = requests.delete(f"https://api.nextdns.io/profiles/{config}/parentalcontrol/categories/gambling",
                                      headers=header)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def dating(self, config, header):
        if self:
            data = {"id": "dating", "active": self}
            setting = requests.post(f"https://api.nextdns.io/profiles/{config}/parentalcontrol/categories",
                                    headers=header, json=data)
        else:
            setting = requests.delete(f"https://api.nextdns.io/profiles/{config}/parentalcontrol/categories/dating",
                                      headers=header)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def piracy(self, config, header):
        if self:
            data = {"id": "piracy", "active": self}
            setting = requests.post(f"https://api.nextdns.io/profiles/{config}/parentalcontrol/categories",
                                    headers=header, json=data)
        else:
            setting = requests.delete(f"https://api.nextdns.io/profiles/{config}/parentalcontrol/categories/piracy",
                                      headers=header)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def socialnetworks(self, config, header):
        if self:
            data = {"id": "social-networks", "active": self}
            setting = requests.post(f"https://api.nextdns.io/profiles/{config}/parentalcontrol/categories",
                                    headers=header, json=data)
        else:
            setting = requests.delete(
                f"https://api.nextdns.io/profiles/{config}/parentalcontrol/categories/social-networks",
                headers=header)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def safesearch(self, config, header):
        setting = {"safeSearch": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/parentalcontrol", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def youtubeRestrictedMode(self, config, header):
        setting = {"youtubeRestrictedMode": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/parentalcontrol", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def blockbypass(self, config, header):
        setting = {"blockBypass": self}
        setting = requests.patch(f"https://api.nextdns.io/profiles/{config}/parentalcontrol", headers=header,
                                 json=setting)
        if setting.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return setting.text

    def blocksite(self, config, header):
        if self in blocksites:
            data = {"id": self, "active": True}
            put = requests.post(f"https://api.nextdns.io/profiles/{config}/parentalcontrol/services/", headers=header,
                                json=data)
            if put.text.__contains__("notFound"):
                raise ConfigNotFound(config)
            else:
                return "OK"
        else:
            print("Allowed: ", blocksites)
            return f"{self} is no valid parameter!"

    def unblocksite(self, config, header):
        if self in blocksites:
            delete = requests.delete(
                f"https://api.nextdns.io/profiles/{config}/parentalcontrol/services/{self}",
                headers=header,
            )
            if delete.text.__contains__("notFound"):
                raise ConfigNotFound(config)
            else:
                return "OK"
        else:
            print("Allowed: ", blocksites)
            return f"{self} is no valid parameter!"


class denylist:
    def list(self, header):
        list = requests.get(
            f"https://api.nextdns.io/profiles/{self}/denylist", headers=header
        )
        if list.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        list = list.json()
        return list

    def blockdomain(self, config, header):
        data = {"id": self, "active": True}
        put = requests.post(f"https://api.nextdns.io/profiles/{config}/denylist/", headers=header, json=data)
        if put.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return put.text

    def unblockdomain(self, config, header):
        delete = requests.delete(
            f"https://api.nextdns.io/profiles/{config}/denylist/{self}",
            headers=header,
        )
        if delete.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return delete.text


class allowlist:
    def list(self, header):
        settings = requests.get(
            f"https://api.nextdns.io/profiles/{self}/allowlist", headers=header
        )
        if settings.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        else:
            return settings.json()

    def add(self, config, header):
        data = {"id": self, "active": True}
        put = requests.post(f"https://api.nextdns.io/profiles/{config}/allowlist/", headers=header, json=data)
        if put.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return put.text

    def remove(self, config, header):
        delete = requests.delete(
            f"https://api.nextdns.io/profiles/{config}/allowlist/{self}",
            headers=header,
        )
        if delete.text.__contains__("notFound"):
            raise ConfigNotFound(config)
        else:
            return delete.text


class analytics:
    def counter(self, header):
        count = requests.get(
            f"https://api.nextdns.io/profiles/{self}/analytics/status",
            headers=header,
        )
        if count.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        count = count.json()
        return count

    def topresolveddomains(self, header):
        top = requests.get(
            f"https://api.nextdns.io/profiles/{self}/analytics/domains?status=default",
            headers=header,
        )
        if top.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        top = top.json()
        return top

    def topblockeddomains(self, header):
        top = requests.get(
            f"https://api.nextdns.io/profiles/{self}/analytics/domains?status=blocked",
            headers=header,
        )
        if top.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        top = top.json()
        return top

    def topalloweddomains(self, header):
        top = requests.get(
            f"https://api.nextdns.io/profiles/{self}/analytics/domains?status=allowed",
            headers=header,
        )
        if top.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        top = top.json()
        return top

    def topdevices(self, header):
        top = requests.get(
            f"https://api.nextdns.io/profiles/{self}/analytics/devices",
            headers=header,
        )
        if top.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        top = top.json()
        return top

    def topclientips(self, header):
        top = requests.get(
            f"https://api.nextdns.io/profiles/{self}/analytics/ips", headers=header
        )
        if top.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        top = top.json()
        return top

    def toprootdomains(self, header):
        top = requests.get(
            f"https://api.nextdns.io/profiles/{self}/analytics/domains?root=true",
            headers=header,
        )
        if top.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        top = top.json()
        return top

    def gafam(self, header):
        gafam = requests.get(
            f"https://api.nextdns.io/profiles/{self}/analytics/destinations?type=gafam",
            headers=header,
        )
        if gafam.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        else:
            return gafam.json()

    def trafficdest(self, header):
        top = requests.get(
            f"https://api.nextdns.io/profiles/{self}/analytics/destinations?type=countries",
            headers=header,
        )
        if top.text.__contains__("notFound"):
            raise ConfigNotFound(self)
        top = top.json()
        return top
