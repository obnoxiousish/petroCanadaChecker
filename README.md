# petroCanadaChecker
A petro canada checker in python, using requests &amp; anticaptcha solving APIs

GPLv3 license

Results print to: "results_newest.txt" in same folder
Emails are loaded from "emails_testing.txt" in the same folder

	pip install python-anticaptcha requests htmlement
  
change to how many threads you desire

	self.threads = 15

stats

	WARNING:root:RealLogins=3:ValidAttempts=17:WrongCaptchas=60

proxies.txt example

	socks5://127.0.0.1:9050
	http://uruser:xdxdpassword@googleProxies.com:31337
	
emails_testing.txt example, if no pw looks up email using pysnus.py

	boobs@look.ca:Password123!
	cockslol@accswave.ca
	penisbutt@ctces.ca

load api key into anticaptcha.txt here is example

	665cc284d30gf8f44b5f726dk587979g

pysnus.py uses a http session for my account on snusbase, itll probably expire at some point, so if u want to use it buy ur own sub and replace the headers+cookies
