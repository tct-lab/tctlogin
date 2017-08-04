# -*- coding: utf-8 -*-
from odoo import http

import os
import sys

import babel.messages.pofile
import base64
import csv
import datetime
import functools
import glob
import hashlib
import imghdr
import itertools
import jinja2
import json
import logging
import operator
import re
import time
import werkzeug.utils
import werkzeug.wrappers
import zlib
from xml.etree import ElementTree
from cStringIO import StringIO


import odoo
import odoo.modules.registry
from odoo.api import call_kw, Environment
from odoo.modules import get_resource_path
from odoo.tools import topological_sort
from odoo.tools.translate import _
from odoo.tools.misc import str2bool, xlwt
from odoo import http
from odoo.http import content_disposition, dispatch_rpc, request, \
                      serialize_exception as _serialize_exception
from odoo.exceptions import AccessError
from odoo.models import check_method_name

sys.path.append(os.path.abspath('addons'))
print sys.path
import web
import auth_signup
import urllib2
import redis
import urllib


import logging
_logger = logging.getLogger(__name__)

from odoo.addons.auth_signup.models.res_users import SignupError

def ensure_db(redirect='/web/database/selector'):

    print("zack ensurre_deb override")
    # This helper should be used in web client auth="none" routes
    # if those routes needs a db to work with.
    # If the heuristics does not find any database, then the users will be
    # redirected to db selector or any url specified by `redirect` argument.
    # If the db is taken out of a query parameter, it will be checked against
    # `http.db_filter()` in order to ensure it's legit and thus avoid db
    # forgering that could lead to xss attacks.
    db = request.params.get('db') and request.params.get('db').strip()

    # Ensure db is legit
    if db and db not in http.db_filter([db]):
        db = None

    if db and not request.session.db:
        # User asked a specific database on a new session.
        # That mean the nodb router has been used to find the route
        # Depending on installed module in the database, the rendering of the page
        # may depend on data injected by the database route dispatcher.
        # Thus, we redirect the user to the same page but with the session cookie set.
        # This will force using the database route dispatcher...
        r = request.httprequest
        url_redirect = r.base_url
        if r.query_string:
            # Can't use werkzeug.wrappers.BaseRequest.url with encoded hashes:
            # https://github.com/amigrave/werkzeug/commit/b4a62433f2f7678c234cdcac6247a869f90a7eb7
            url_redirect += '?' + r.query_string
        response = werkzeug.utils.redirect(url_redirect, 302)
        request.session.db = db
        abort_and_redirect(url_redirect)

    # if db not provided, use the session one
    if not db and request.session.db and http.db_filter([request.session.db]):
        db = request.session.db

    # if no database provided and no database in session, use monodb
    if not db:
        db = db_monodb(request.httprequest)

    # if no db can be found til here, send to the database selector
    # the database selector will redirect to database manager if needed
    if not db:
        werkzeug.exceptions.abort(werkzeug.utils.redirect(redirect, 303))

    # always switch the session to the computed db
    if db != request.session.db:
        request.session.logout()
        abort_and_redirect(request.httprequest.url)

    request.session.db = 'tctdemo1'


class Tctlogin(web.controllers.main.Home,auth_signup.controllers.main.AuthSignupHome):
    @http.route('/tctlogin/tctlogin/', auth='public')
    def index(self, **kw):
        return "Hello, world"

    @http.route('/tctlogin/tctlogin/objects/', auth='public')
    def list(self, **kw):
        return http.request.render('tctlogin.listing', {
            'root': '/tctlogin/tctlogin',
            'objects': http.request.env['tctlogin.tctlogin'].search([]),
        })

    @http.route('/tctlogin/tctlogin/objects/<model("tctlogin.tctlogin"):obj>/', auth='public')
    def object(self, obj, **kw):
        return http.request.render('tctlogin.object', {
            'object': obj
        })


    @http.route('/wechat/login', type='http', auth="none" ,csrf=False)
    def wechat_login(self, redirect=None, **kw):
        print("zack wechat login")
        return http.redirect_with_hash('https://open.weixin.qq.com/connect/oauth2/authorize?appid=wwbf94872d6daf233a&redirect_uri=tctodooauth.cq-tct.com/wechat/auth&response_type=code&scope=SCOPE&agentid=1000013&state=STATE#wechat_redirect')

    @http.route('/wechat/auth', type='http', auth="none", csrf=False)
    def wechat_auth(self, redirect=None, **kw):
        print("zack wechat auth")
        code = ''
        r = redis.Redis(host='127.0.0.1', port=6379, db=0)

        token = r.get('tctodooauth_token')

        if 'code' in request.params:
            code = request.params['code']
            print('code:' + code)

        if token:
            print(token)
        else:
            print("get new token")
            token_url ="https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=wwbf94872d6daf233a&&corpsecret=sfSXSqVzUo9eSVgeKRmzaUa1pgwIqqGX8gTPlpC6bE8"
            req = urllib2.Request(token_url)
            result = urllib2.urlopen(req)  # 发起GET http服务
            res = result.read()  # 把结果通过.read()函数读取出来
            token_info = json.loads(res)
            print(str(token_info))
            token = token_info["access_token"]
            r.setex("tctodooauth_token", token, 7000)

        #get userinfo
        user_uri ="https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?access_token=%s&code=%s" % (token,code)
        print("user uri:"+user_uri)
        user_req = urllib2.Request(user_uri)
        user_result = urllib2.urlopen(user_req)
        user_dic = user_result.read()
        user_info = json.loads(user_dic)
        print(str(user_info))

        moreinfo_uri = "https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=%s&userid=%s" % (token,user_info["UserId"])
        moreinfo_req = urllib2.Request(moreinfo_uri)
        moreinfo_result = urllib2.urlopen(moreinfo_req)
        moreinfo_dic = moreinfo_result.read()
        more_info = json.loads(moreinfo_dic)


        #try to create this user

        url = 'http://tctodooauth.cq-tct.com/web/signup'

        values = {
            'login': more_info["userid"].encode('utf-8') ,
            'password': more_info["userid"].encode('utf-8') ,
            'confirm_password': more_info["userid"].encode('utf-8') ,
            'name': more_info["name"].encode('utf-8')
        }

        createuser_data = urllib.urlencode(values)  # 编码工作
        createuser_req = urllib2.Request(url, createuser_data)  # 发送请求同时传data表单
        createuser_response = urllib2.urlopen(createuser_req)  # 接受反馈的信息
        the_page = createuser_response.read()  # 读取反馈的内容

        login_url = 'http://tctodooauth.cq-tct.com/web/login?wechatname=%s&access_token=%s&code=%s' % (more_info["userid"].encode('utf-8'),token,code )
        print(login_url)

        return http.redirect_with_hash(login_url)



    @http.route('/web/login', type='http', auth="none" ,csrf=False)
    def web_login(self, redirect=None, **kw):
        print("zack override this route")

        if 'access_token' in request.params and 'code' in request.params:
            user_uri = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?access_token=%s&code=%s" % (request.params['access_token'], request.params['code'])
            print("user uri:" + user_uri)
            user_req = urllib2.Request(user_uri)
            user_result = urllib2.urlopen(user_req)
            user_dic = user_result.read()
            user_info = json.loads(user_dic)
            if user_info['errcode'] != 0:
                print(user_info)
                return "bad auth"
            else:
                print("you are ok to continue")


        wechatname = ""
        if 'wechatname' in request.params:
            wechatname = request.params['wechatname']
            print(request.params['wechatname'])


        ensure_db()
        request.params['login_success'] = False
        if request.httprequest.method == 'GET' and redirect and request.session.uid:
            return http.redirect_with_hash(redirect)

        if not request.uid:
            request.uid = odoo.SUPERUSER_ID

        values = request.params.copy()
        try:
            values['databases'] = http.db_list()
        except odoo.exceptions.AccessDenied:
            values['databases'] = None

        old_uid = request.uid

        # if wechatname:
        #     uid = request.session.authenticate(request.session.db, wechatname, wechatname)
        # else:
        #     uid = request.session.authenticate(request.session.db, 'admin', 'admin')



        if not wechatname:
            print ('no wechatname:')
            uid = request.session.authenticate(request.session.db, "36757049@qq.com", "123456")
        else:
            print ('have wechatname:')
            uid = request.session.authenticate(request.session.db, wechatname, wechatname)



        if uid is not False:
            request.params['login_success'] = True
            if not redirect:
                redirect = '/web'
            return http.redirect_with_hash(redirect)
        request.uid = old_uid
        values['error'] = _("Wrong login/password")

        return request.render('web.login', values)

    @http.route('/web/signup', type='http', auth="none" ,csrf=False)
    def web_auth_signup(self, *args, **kw):
        print("zack override /web/signup")
        qcontext = self.get_auth_signup_qcontext()

        if not qcontext.get('token') and not qcontext.get('signup_enabled'):
            raise werkzeug.exceptions.NotFound()

        if 'error' not in qcontext and request.httprequest.method == 'POST':
            try:
                self.do_signup(qcontext)
                return self.web_login(*args, **kw)
            except (SignupError, AssertionError), e:
                if request.env["res.users"].sudo().search([("login", "=", qcontext.get("login"))]):
                    qcontext["error"] = _("Another user is already registered using this email address.")
                else:
                    _logger.error(e.message)
                    qcontext['error'] = _("Could not create a new account.")

        return request.render('auth_signup.signup', qcontext)


    @http.route('/web/login_normal', type='http', auth="none")
    def web_tct_normal_login(self, redirect=None, **kw):
        print("zack web tct login normal")
        ensure_db()
        request.params['login_success'] = False
        if request.httprequest.method == 'GET' and redirect and request.session.uid:
            return http.redirect_with_hash(redirect)

        if not request.uid:
            request.uid = odoo.SUPERUSER_ID

        values = request.params.copy()
        try:
            values['databases'] = http.db_list()
        except odoo.exceptions.AccessDenied:
            values['databases'] = None

        if request.httprequest.method == 'POST':
            old_uid = request.uid
            uid = request.session.authenticate(request.session.db, request.params['login'], request.params['password'])
            if uid is not False:
                request.params['login_success'] = True
                if not redirect:
                    redirect = '/web'
                return http.redirect_with_hash(redirect)
            request.uid = old_uid
            values['error'] = _("Wrong login/password")
        return request.render('web.login', values)