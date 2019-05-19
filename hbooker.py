#!/bin/env python3
import json;
import base64;
import hashlib;
import http.client;
import urllib.parse;

ksykey = hashlib.sha256(b'zG2nSeEfSHfvTCHy5LCcqtBbQehKNLXn').digest();

class FuckYouException(Exception):
  def __str__ (self): return 'Fuck You !';
  def __repr__(self): return 'Fuck You !';
while True:
  try:
    import Crypto.Cipher.AES;
    def decryptHbk(data, key):
      data = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, b'\0'*16).decrypt(base64.b64decode(data));
      return data[:-data[-1]].decode('utf8');
    break;
  except ModuleNotFoundError: None;
  try:
    import pyaes;
    def decryptHbk(data, key):
      data = base64.b64decode(data);
      ciph = pyaes.AESModeOfOperationCBC(key, b'\0'*16);
      decrypted, nextblock, data = b'', data[0:16], data[16:];
      while nextblock != b'':
        decrypted += ciph.decrypt(nextblock);
        nextblock, data = data[0:16], data[16:];
      return decrypted[:-decrypted[-1]].decode('utf8');
    break;
  except ModuleNotFoundError: None;
  raise FuckYouException();
class HBException(Exception):
  def __init__(self, code, tip):
    self.code = code;
    self.tip  = tip;
def decryptKsy(data):
  return decryptHbk(data, ksykey);
def decryptKey(data, keyStr):
  return decryptHbk(data, hashlib.sha256(keyStr.encode('utf8')).digest());
def requestHb(api, token, args):
  reqBody = {'app_version': '2.1.032'};
  if token: reqBody = {**reqBody, **token};
  if args:  reqBody = {**reqBody, **args};
  reqBody = urllib.parse.urlencode(reqBody);
  conn = http.client.HTTPSConnection('app.hbooker.com');
  conn.request('POST', api, reqBody, headers={'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Android'});
  resp = json.loads(decryptKsy(conn.getresponse().read()), encoding='utf8');
  conn.close();
  if int(resp['code']) != 100000:
    raise HBException(resp['code'], resp['tip']);
  return resp['data'];

def hbLogin(login_name, passwd):
  args = {'login_name': login_name, 'passwd': passwd};
  jobj = requestHb('/signup/login', None, args);
  tokn = {'login_token': jobj['login_token'], 'account': jobj['reader_info']['account']};
  return HBookerUser(tokn);
class HBookerUser():
  def __init__(self, token):
    self.token = token;
    for hbapi in hbapis.items(): setattr(self, hbapi[0], hbapi[1](self));
  def __str__ (self): return str(self.token);
  def __repr__(self): return str(self.token);
  def request (self, api, args=None):
    return requestHb(api, self.token, args);
class HBookerSubAPI():
  def __init__(self, hu): self.hu = hu;
#
def newApiClass(apidir, apidefs):
  Locals, classdef = {}, 'class sa(HBookerSubAPI): None;';
  exec(classdef, None, Locals);
  sa = Locals['sa'];
  for apidef in apidefs:
    fun = apidef[0];
    api = '%s/%s'%(apidir,fun);
    afunc = newApiFunc(api, apidef[1]);
    setattr(sa, fun, afunc);
  return sa;
def newApiFunc(api, argdefs):
  afuncdef = 'def af(self,%s):return self.hu.request(\'%s\',{%s});';
  adefstr = [];
  dictstr = [];
  for adef in argdefs:
    if type(adef)==str:
      aname = adef;
      adefstr.append(aname);
    else:
      aname = adef[0];
      adefstr.append('%s=%s'%(adef[0], repr(adef[1])));
    dictstr.append('\'%s\':%s'%(aname,aname));
  adefstr = ','.join(adefstr);
  dictstr = ','.join(dictstr);
  fdefstr = afuncdef%(adefstr,api,dictstr);
  Locals  = {};
  exec(fdefstr, None, Locals);
  return Locals['af'];

hbapis = {};
def apiNewDefLine(apidef):
  arg = apidef.partition(' ');
  url, arg = arg[0], arg[2];
  arg = arg.split(' ') if len(arg) else ();
  for i in range(len(arg)):
    if '=' in arg[i]:
      arg[i] = tuple(arg[i].split('='));
  url = url.rpartition('/');
  l0 = url[0][1:];
  l1 = url[0];
  l2 = url[2];
  if l0 not in hbapis: hbapis[l0] = (l1, []);
  hbapis[l0][1].append([l2, tuple(arg)]);
with open('apis.txt', 'r') as fp:
  for ln in fp:
    ln = ln.replace('\n', '');
    if len(ln) > 1 and ln[0:2] == '#/': apiNewDefLine(ln[1:]);
for ky in hbapis.keys(): hbapis[ky] = newApiClass(*hbapis[ky]);