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
with open(__file__, 'r') as fp:
  for ln in fp:
    ln = ln.replace('\n', '');
    if len(ln) > 1 and ln[0:2] == '#/': apiNewDefLine(ln[1:]);
for ky in hbapis.keys(): hbapis[ky] = newApiClass(*hbapis[ky]);

# Finding Books
#   Search Suggestions
#/book/get_official_tag_list
#/bookcity/get_hot_key_list
#/bookcity/get_search_keys key
#   Search
#/bookcity/get_tag_book_list tag type=0 count=10 page=0
#/bookcity/get_filter_search_book_list key category_index=0 tags=[] order= filter_word= filter_uptime= up_status= is_paid= count=10 page=0
#/booklist/get_search_booklist_by_listname key is_suggest count=1 page=0
#   Booklists List
#/bookcity/get_book_lists type count=10 page=0
#   Related Books
#/bookshelf/get_bookself_reommend_list
#/bookcity/get_book_correlation_lists book_id type=3 list_num=0 count=10 page=0
#   Bookshelf
#/bookshelf/get_shelf_list
#/bookshelf/get_shelf_book_list shelf_id direction=prev last_mod_time=0
#/bookshelf/get_shelf_book_list_new shelf_id order=zonghe count=100 page=0
#   Booklist
#/bookcity/get_booklist_detail list_id count=10 page=0
#   Categories
#/bookcity/get_category_book_list category_index type=1 count=10 page=0

#   Book Information
#/book/get_info_by_id book_id
#   Divisions
#/book/get_division_list book_id
#/chapter/get_updated_chapter_by_division_id division_id last_update_time=0
#   Chapters
#/chapter/get_chapter_permission_list book_id
#/chapter/get_chapter_info chapter_id
#/chapter/get_chapter_command chapter_id
#/chapter/get_cpt_ifm chapter_id chapter_command

#   Comments
#   Book Review
#/book/get_review_list book_id type=0 filter_type= count=10 page=0
#/book/get_review_comment_list review_id count=10 page=0
#/book/like_review review_id
#/book/unlike_review review_id
#/book/add_review_comment review_id comment_content
#/book/add_review_comment_reply old_reader_id comment_id reply_content
#   Chapter(Paragraph) Review
#/chapter/get_tsukkomi_num chapter_id
#/chapter/get_paragraph_tsukkomi_list_new chapter_id paragraph_index filter_type= count=5 page=0

#   Book Tags
#/book/get_book_tag_list book_id
#/book/like_tag tag_id
#/book/unlike_tag tag_id
#/book/can_add_tag book_id
#   Book Fans
#/book/get_book_fans_list book_id count=10 page=0
#/book/get_book_operate_list book_id count=10 page=0
#   Bookmarks
#/book/get_bookmark_list book_id count=50 page=0

#   Reader
#/reader/get_my_info reader_id=
#/reader/get_homepage_info reader_id
#/reader/follow reader_id
#/reader/unfollow reader_id
#   Reader Property
#/reader/get_prop_info
#/reader/get_wallet_info
#   Information Center
#/reader/get_unread_num
#/reader/get_message_at_list count=10 page=0
#/reader/get_message_comment_list count=10 page=0
#/reader/get_message_reader_list count=20 page=0
#/reader/get_message_sys_list count=10 page=0
#/reader/set_is_read_at message_id
#   Reader's Booklist
#/booklist/get_my_booklist count=10 page=0
#/booklist/get_favor_booklist count=10 page=0
#/booklist/favor_booklist list_id
#/booklist/disfavor_booklist list_id
#   Reader's Comments
#/reader/get_reader_bbs_list reader_id count=10 page=0
#/reader/get_reader_review_list reader_id count=10 page=0
#/reader/get_reader_tsukkomi_list reader_id count=10 page=0
#   Tasks
#/task/get_all_task_list
#/reader/get_task_list