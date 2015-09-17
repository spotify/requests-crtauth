requests-crtauth
================
A plugin to support [crtauth authentication](https://github.com/spotify/crtauth) in [Python Requests](http://www.python-requests.org/).

Usage
=====
requests-crtauth works as an authentication plugin for Python Requests. See the [authentication documentation](http://www.python-requests.org/en/latest/user/authentication/) for more details. The following arguments may be provided to a new instance of `HttpCrtAuth`:
```
username: User to authenticate as. Defaults to $USER.
private_key: A PEM encoded private key string. Overrides signer.
signer: A crtauth SigningPlug instance. Defaults to using the SSH agent (AgentSigner).
version: Integer version of the crtauth protocol. Defaults to version 1.
```

Here's an example.
```python
In [1]: import requests, requests_crtauth, json, logging
In [2]: logging.basicConfig(level=logging.DEBUG)
In [3]: session = requests.Session()
# HttpCrtAuth() will default to authenticating with your $USER env variable and a key from your SSH agent.
# To specify an explicit key: requests_crtauth.HttpCrtAuth(username='negz', private_key='key data as a string')
In [4]: session.auth = requests_crtauth.HttpCrtAuth()
In [5]: data = json.dumps({'comment': 'I\'m a comment!'})
In [6]: headers = {'content-type': 'application/json; charset=utf-8'}
In [7]: response = session.put('https://db.spotify.net/v1/things/yomaris', data=data, headers=headers)
INFO:requests.packages.urllib3.connectionpool:Starting new HTTPS connection (1): db.spotify.net
DEBUG:requests.packages.urllib3.connectionpool:"PUT /v1/things/yomaris HTTP/1.1" 401 12
DEBUG:root:Sending challenge request
DEBUG:requests.packages.urllib3.connectionpool:"HEAD /_auth HTTP/1.1" 200 0
DEBUG:root:Sending response to challenge REDACTED
DEBUG:requests.packages.urllib3.connectionpool:"HEAD /_auth HTTP/1.1" 200 0
DEBUG:root:Stored CHAP token REDACTED
DEBUG:root:Using newly stored CHAP token.
DEBUG:requests.packages.urllib3.connectionpool:"PUT /v1/things/yomaris HTTP/1.1" 200 None
In [8]: response.ok
Out[8]: True
```
