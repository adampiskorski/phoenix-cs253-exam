## Imports
import webapp2
from google.appengine.api import users

## Templates
import os
import jinja2 

## Validation
import re

## Db
from google.appengine.ext import db
from google.appengine.api import memcache 
from collections import namedtuple

## Hashing
import hmac
import string
import random
import hashlib

## Date time
import time

## API
import json

## Debug
import logging

## Cookies
cookie_secret = "chutR2rex69hEg$c$ecRA@athuhat&tH=r#Sp#T&g7cr97+Afan6!r?W$zU-puwr"

## Jinja
jinja_environment = jinja2.Environment(autoescape=False, 
     loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates'))) 

def render_jinja(template, **params):
	t = jinja_environment.get_template(template)
	return t.render(params)


class Validate():
	username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	@classmethod
	def username(self, username):
		return username and self.username_re.match(username)

	password_re = re.compile(r"^.{3,20}$")
	@classmethod
	def password(self, password):
		return password and self.password_re.match(password)

	email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
	@classmethod
	def email(self, email):
		return self.email_re.match(email)

	COOKIE_RE = re.compile(r'.+=;\s*Path=/')
	@classmethod
	def cookie(self, cookie):
		return cookie and self.COOKIE_RE.match(cookie)


class Cookie(webapp2.RequestHandler):
	@classmethod
	def val_make(self, val):
		val = str(val)
		hashh = hmac.new(cookie_secret, val, hashlib.sha256).hexdigest()
		return val + '|' + hashh

	@classmethod
	def send(self, response, name, val):
		if val == 'empty':
			cookie_val = ''
		else:
			cookie_val = self.val_make(val)
		response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %(name, cookie_val))

	@classmethod
	def val_verify(self, val):
		vals = val.split('|')
		if val == self.val_make(vals[0]):
			return vals[0]

	@classmethod
	def verify(self, request, cookie_name):
		cookie_val = request.cookies.get(cookie_name, None)
		return cookie_val and self.val_verify(cookie_val)


class Cache(webapp2.RequestHandler):
	@classmethod
	def read(self, key, read_func):
		logging.info('Cache.read: Start, key: %s, read_func: %s' %(key, read_func))
		client = memcache.Client()
		r = client.get(key)
		if not r:
			logging.info('Cache.read: Miss, running Cache.create')
			return self.create(key, read_func)
		else:
			logging.info('Cache.read: Return %s' %r)
			return r

	@classmethod
	def refresh(self, key, read_func):
		logging.info('Cache.refresh: Start, key: %s, read_func: %s' %(key, read_func))
		client = memcache.Client()
		attempts = 0
		r = None
		while not r and attempts < 10:
			q = client.gets(key)
			val = eval(read_func+'('+"key"+')')
			r = client.cas(key, val)
			attempts += 1
		logging.info('Cache.refresh: Return, CAS: %s, attempts: %s, val: %s' %(r, attempts, val))
		return r and val

	@classmethod
	def create(self, key, read_func):
		logging.info('Cache.create: Start, key: %s, read_func: %s' %(key, read_func))
		client = memcache.Client()
		if client.get(key):
			logging.info('Cache.create: Key already exists, running Cache.refresh')
			return Cache.refresh(key, read_func)
		else:
			val = eval(read_func+'('+"key"+')')
			r = client.add(key, val)
			logging.info('Cache.create: New key added, Return val: %s' %val)
			return val

	@classmethod
	def update(self, key, read_func, val):
		logging.info('Cache.update: Start, key: %s, read_func: %s, val: %s' %(key, read_func, val))
		client = memcache.Client()
		r = client.add(key, val)
		if not r:
			logging.info('Cache.update: Key exists, running Cache.refresh')
			return self.refresh(key, read_func)
		else:
			logging.info('Cache.update: Return %s' %r)
			return r

	@classmethod
	def lock(self, username):
		logging.info('Cache.lock: Start, username: %s' %username)
		client = memcache.Client()
		key = "lock: %S" %username
		q = client.add(key, "null")
		logging.info('Cache.lock: Return %s' %q)
		return q


## Start of APP
class BaseHandler(webapp2.RequestHandler):
	def render(self, template, **kw): 
		kw['user'] = self.user
		self.response.out.write(render_jinja(template, **kw))

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		user_id = Cookie.verify(self.request, 'user_id')
		self.user = user_id and Users.get_by_id(int(user_id))


class Users(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringListProperty(required = True)
	email = db.EmailProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def make_passhash(self, username, password):
		salt = ''.join(random.sample(string.letters, 52))
		hashh = hmac.new(salt, username + password, hashlib.sha512).hexdigest()
		return [hashh, salt]

	@classmethod
	def verify_passhash(self, username, password, hashsalt):
		salt = str(hashsalt[1])
		hashh = hmac.new(salt, username + password, hashlib.sha512).hexdigest()
		return str(hashsalt[0]) == hashh


class Signup(BaseHandler):
	def get(self):
		self.render("signup.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		params = {'username': username, 'email': email}
		user_exists = False
		error = False

		if Validate.username(username):
			user_key = Users.all(keys_only=True).filter('username =', username).get()
			if user_key:
				user_exists = True
				error = True
				params['error_username'] = 'Error: This username is already registered'
		else:
			params['error_username'] = "Error: Your username must start with letters and contain no spaces."
			error = True

		if not user_exists:
			if not Validate.password(password):
				params['error_password'] = "Error: Your password must be between 3 and 20 characters long."
				error = True
			else:
				if password != verify:
					params['error_password_verify'] = "Error: Your passwords must match each other."
					error = True

			if email != '':
				if not Validate.email(email):
					params['error_email'] = "Error: If you provide an email, then it must be valid."
					error = True

		if error:
			self.render("signup.html", **params)
		else:
			salt = Users.make_passhash(username, password)
			if email != '':
				a = Users(username=username, password=salt, email=email)
			else:
				a = Users(username=username, password=salt)

			user_id = a.put().id()
			Cookie.send(self.response, 'user_id', user_id)
			self.redirect('/')


class Login(BaseHandler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		params = {'username': username}
		error = False

		if Validate.username(username) and Validate.password(password):
			q = Users.all().filter('username =', username).get()
			if q:
				user_id = q.key().id()
				salt = Users.verify_passhash(username, password, q.password)
			else:
				error = True
		else:
			error = True

		if not error and salt:
			Cookie.send(self.response, 'user_id', user_id)
			self.redirect('/')
		else:
			params['error'] = 'Invalid username and/or password'
			self.render("login.html", **params)


class Logout(BaseHandler):
	def get(self):
		Cookie.send(self.response, 'user_id', 'empty')
		r = self.request.headers['Referer']
		self.redirect(r)


class Welcome(BaseHandler):
	def get(self):
		user_id = Cookie.verify(self.request, 'user_id')

		if not user_id:
			self.redirect('/signup') # No cookie or hacked cookie
		else:
			user_account = Users.get_by_id(int(user_id))
			if user_account != None: 
				self.render("welcome.html", response = "Welcome " + user_account.username + "!")
			else:
				params['error'] = 'User no longer exists!'
				self.render("login.html", **params) # Cookie valid but user no longer exists


class Wiki(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	user = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def write(self, subject, content, user):
		logging.info('Wiki.write: Start, subject: %s' %subject)
		a = Wiki(subject=subject, content=content, user=user)
		key = a.put()
		logging.info('Wiki.write: Wrote to Db')
		obj = Wiki.get(key)
		Cache.update('post_id='+str(key.id()), 'Wiki.read_by_id_db', obj)
		Cache.refresh('subj='+subject, 'Wiki.read_by_subj_db')
		Cache.refresh('subj_hist='+subject, 'Wiki.read_by_subjhist_db')
		logging.info('Wiki.write: Return %s' %key)
		return key

	@classmethod
	def read_by_id_mem(self, post_id):
		logging.info('Wiki.read_by_id_mem: Start, id: %s' %post_id)
		key = 'post_id='+str(post_id)
		read_func = 'Wiki.read_by_id_db'
		r = Cache.read(key, read_func)
		logging.info('Wiki.read_by_id_mem: Return %s' %r)
		return r

	@classmethod
	def read_by_id_db(self, key):
		logging.info('Wiki.read_by_id_db: Start, key: %s' %key)
		post_id = int(key[8:])
		r = Wiki.get_by_id(post_id)
		memcache.set('db_access', time.time())
		logging.info('Wiki.read_by_id_db: Return %s' %r)
		return r

	@classmethod
	def read_by_subj_mem(self, subj):
		logging.info('Wiki.read_by_subj_mem: Start, subj: %s' %subj)
		key = 'subj='+str(subj)
		read_func = 'Wiki.read_by_subj_db'
		r = Cache.read(key, read_func)
		logging.info('Wiki.read_by_subj_mem: Return %s' %r)
		return r

	@classmethod
	def read_by_subj_db(self, key):
		logging.info('Wiki.read_by_subj_db: Start, key: %s' %key)
		subj = key[5:]
		r = Wiki.all().filter('subject =', subj).order('-created').get()
		memcache.set('db_access', time.time())
		logging.info('Wiki.read_by_subj_db: Return %s' %r)
		return r

	@classmethod
	def read_by_subjhist_mem(self, subj):
		logging.info('Wiki.read_by_subjhist_mem: Start, subj: %s' %subj)
		key = 'subj_hist='+str(subj)
		read_func = 'Wiki.read_by_subjhist_db'
		r = Cache.read(key, read_func)
		logging.info('Wiki.read_by_subjhist_mem: Return %s' %r)
		return r

	@classmethod
	def read_by_subjhist_db(self, key):
		logging.info('Wiki.read_by_subjhist_db: Start, key: %s' %key)
		subj = key[10:]
		logging.info('Wiki.read_by_subjhist_db: subj: %s' %subj)
		q = Wiki.all().filter('subject =', subj).order('-created').run(limit=100)
		memcache.set('db_access', time.time())
		r = list(q)
		logging.info('Wiki.read_by_subjhist_db: Return %s' %r)
		return r

class Test(BaseHandler):
	def get(self):
		#subj = '/test1'
		#key = 'subj=/test2'
		#response = Wiki.all().filter('subject =', subj).order('created').get()
		#q = Wiki.all().filter('subject =', subj).order('created').run(limit=100)
		#r = list(q)
		#r = Wiki.read_by_subj_mem(subj).content
		#r = Wiki.read_by_subj_db(key).content
		#r = [i.content for i in Wiki.read_by_subjhist_db(key)]
		#r = self.request.headers['Referer']
		#client = memcache.Client()
		#r = client.get(key)
		#r = Cache.read(key, 'Wiki.read_by_subj_db').key().id()
		r = "error?"
		user = users.get_current_user()
		if user:
			r = str([user.nickname(), user.email(), user.user_id(), users.create_login_url("/test"), users.create_logout_url("/test")])
		else:
			return self.redirect(users.create_login_url("/test"))
		self.render("welcome.html", response = r)

class Home(BaseHandler):
	def get(self):
		self.render("home.html")

class EditPage(BaseHandler):
	def get(self, subject):
		if not self.user:
			return self.redirect('/login')
		params = {'subject':subject}
		WikiPage = Wiki.read_by_subj_mem(subject)
		if WikiPage:
			params['content'] = WikiPage.content
		self.render('editpage.html', **params)

	def post(self, subject):
		content = self.request.get("content")
		params = {'subject': subject, 'content': content} 

		if not self.user:
			params['error'] = "You must be logged in to post or edit a page!"
			return self.render('editpage.html', **params)

		if subject and content:
			user = self.user and self.user.username
			wiki_key = Wiki.write(subject, content, user)
			if wiki_key:
				self.redirect(subject)
			else:
				params['error'] = "Failed to write to Db!"
				self.render('editpage.html', **params)
		else:
			params['error'] = "Both fields need to be filled in!"
			self.render('editpage.html', **params)


class WikiPage(BaseHandler):
	def get(self, subject):
		WikiPage = Wiki.read_by_subj_mem(subject)
		db_access = int(time.time() - memcache.get('db_access'))

		if not WikiPage:
			return self.redirect('/_edit%s' %subject)

		options = '<a class="link" href="/_edit%s">Edit</a> | <a class="link" href="/_history%s">Histroy</a>' %(subject, subject)
		params = {'WikiPage':WikiPage, 'db_access':db_access, 'options':options}
		self.render("wikipage.html", **params)

class WikiPage_his(BaseHandler):
	def get(self, subject):
		WikiPages = Wiki.read_by_subjhist_mem(subject)
		db_access = int(time.time() - memcache.get('db_access'))

		if not WikiPages:
			return self.redirect(subject)

		options = '<a class="link" href="/_edit%s">Edit last version</a>' %subject
		params = {'WikiPages':WikiPages, 'db_access':db_access, 'subject':subject, 'options':options}
		self.render("wikipage_hist.html", **params)

class Json_by_id(BaseHandler):
	def get(self, post_id):
		self.response.headers['Content-Type'] = 'application/json; charset=utf-8'
		post = Wiki.read_by_subj_mem(subject)

		if not post:
			self.error(404)
			return

		json_post = {
			'subject': post.subject,
			'content': post.content,
			'user': post.user,
			'created': post.created.strftime('%a %b %d %H.%M.%S %Y'),
			'last_modified': post.last_modified.strftime('%a %b %d %H.%M.%S %Y')
		}

		self.write(json.dumps(json_post))

class Flush(webapp2.RequestHandler):
	def get(self):
		client = memcache.Client()
		r = client.flush_all()
		logging.info('Memcache flush: %s'%r)
		self.redirect('/')

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([
	#webapp2.Route(r'/', handler=Home),
    webapp2.Route(r'/signup', handler=Signup),
    webapp2.Route(r'/login', handler=Login),
    webapp2.Route(r'/logout', handler=Logout),
    webapp2.Route(r'/welcome', handler=Welcome),
	webapp2.Route(r'/flush', handler=Flush),
	(r'/test', Test),
	(r'/_history' + PAGE_RE, WikiPage_his),
	(r'/_edit' + PAGE_RE, EditPage),
	webapp2.Route(r'/<post_id:PAGE_RE>.json', handler=Json_by_id, name='post_id'),
	(PAGE_RE, WikiPage)
],
debug=True) 