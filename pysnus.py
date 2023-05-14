import requests
import htmlement


class main:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://snusbase.com',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Referer': 'https://snusbase.com/search',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'auth': 'sbh6an8bnv27a0ysezonnr0tc0f7d2',
        }
        )

        self.session.cookies.update(
            {
                'a': '8v3kghumldrim45p9jags1bdie',
                'lg': 'ca03fd72644dd46bfc9920e9a685782eb1e52627ac9446355f1eb4ba50ce2b69',
                'rm': 'clFGSlU1R3FnRTRMSWVwOVJuRkh3QT09%3A%3AGFGcFhjpUJjTT8ddn0UUfA%3D%3D',
            }
        )

    def search(self, email):
        self.searchData = {
            'csrf_token': 'bc1d0ffb24060741fd2e0a8e840c5061525264',
            'term': email,
            'searchtype': 'email',
        }

        self.searchResponse = self.session.post(
            'https://snusbase.com/search', data=self.searchData)
        self.parsedHTML = htmlement.fromstring(self.searchResponse.text)
        # print(self.searchResponse.text)
        return self.parsedHTML

    def getHashedPassword(self, email, convert=True):
        self.hashedPasswords = []
        self.clearTextPasswords = []

        self.search(email)

        # print(self.searchResponse.text)

        for td in self.parsedHTML.iterfind(".//td"):
            try:
                if 'xhash' in td.items()[1][1]:
                    # print(td.text)
                    self.hashedPasswords.append(td.text)
            except Exception as e:
                # print(e)
                continue

        if not convert:
            return self.hashedPasswords

        for pw in self.hashedPasswords:
            for i in range(3):
                try:
                    self.clearTextRequest = self.session.get(
                        f'https://api.snusbase.com/legacy/hash-lookup/{pw}')
                    self.clearTextPWJSON = self.clearTextRequest.json()
                    #print(self.clearTextPWJSON)
                    break
                except Exception as e:
                    print(e)
                    continue
                
            try:
                if self.clearTextPWJSON['found']:
                    try:
                        if self.clearTextPWJSON['password'] not in self.clearTextPasswords:
                            self.clearTextPasswords.append(self.clearTextPWJSON['password'])
                    except KeyError as e:
                        print(e)
                        continue
            except Exception as e:
                print(e)
                return False

        #print(self.clearTextPasswords)
        return self.clearTextPasswords


if __name__ == "__main__":
    snus = main()
    # snus.search(email='obnoxious@dongcorp.org')
    print(snus.getHashedPassword('kabilan.09@gmail.com', convert=True))
