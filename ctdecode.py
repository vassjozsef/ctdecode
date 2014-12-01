import sys
import base64
import json
import datetime
import urlparse

def base64url_decode(input):
  input += '=' * (4 - (len(input) % 4))
  return base64.urlsafe_b64decode(input)

if len(sys.argv) != 2:
  print 'Usage:' + sys.argv[0] + ' capability_token'
  sys.exit(1)

token = sys.argv[1]
parts = token.split('.')
if len(parts) != 3:
  print 'Invalid capability token'
  sys.exit(1)

payload = json.loads(base64url_decode(parts[1]))
print 'Account Sid:', payload['iss']
print 'Expires:', payload['exp'], ' (' + datetime.datetime.fromtimestamp(payload['exp']).strftime('%Y-%m-%d %H:%M:%S') + ')'
scopes = payload['scope'].split(' ')
for s in scopes:
  if s.startswith('scope:client:incoming'):
    print 'Incoming: YES'
    params = urlparse.parse_qs(s[22:])
    print '  Client:', params['clientName'][0]
  if s.startswith('scope:client:outgoing'):
    print 'Outgoing: YES'
    params = urlparse.parse_qs(s[22:])
    print '  Application SID:', params['appSid'][0]
    if params.has_key('clientName'):
      print '  Client:', params['clientName'][0]
    if params.has_key('appParams'):
      app = urlparse.parse_qs(params['appParams'][0])
      print '  Application params: {'
      for i in app:
        print '    ', i, '=', app[i][0]
      print '  }'
