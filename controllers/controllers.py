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
        print("zack override this route")
        return "Hello, wechatlogin"


    # @http.route('/web/login', type='http', auth="none" ,csrf=False)
    # def web_login(self, redirect=None, **kw):
    #     print("zack override this route")
    #     wechatname = ""
    #     if 'wechatname' in request.params:
    #         wechatname = request.params['wechatname']
    #         print(request.params['wechatname'])


    #     ensure_db()
    #     request.params['login_success'] = False
    #     if request.httprequest.method == 'GET' and redirect and request.session.uid:
    #         return http.redirect_with_hash(redirect)

    #     if not request.uid:
    #         request.uid = odoo.SUPERUSER_ID

    #     values = request.params.copy()
    #     try:
    #         values['databases'] = http.db_list()
    #     except odoo.exceptions.AccessDenied:
    #         values['databases'] = None

    #     old_uid = request.uid

    #     # if wechatname:
    #     #     uid = request.session.authenticate(request.session.db, wechatname, wechatname)
    #     # else:
    #     #     uid = request.session.authenticate(request.session.db, 'admin', 'admin')

    #     print ('wechatname:'+wechatname)

    #     if not wechatname:
    #         wechatname = "test"

    #     uid = request.session.authenticate(request.session.db, wechatname, wechatname)



    #     if uid is not False:
    #         request.params['login_success'] = True
    #         if not redirect:
    #             redirect = '/web'
    #         return http.redirect_with_hash(redirect)
    #     request.uid = old_uid
    #     values['error'] = _("Wrong login/password")

    #     return request.render('web.login', values)

    # @http.route('/web/signup', type='http', auth="none" ,csrf=False)
    # def web_auth_signup(self, *args, **kw):
    #     print("zack override /web/signup")
    #     qcontext = self.get_auth_signup_qcontext()

    #     if not qcontext.get('token') and not qcontext.get('signup_enabled'):
    #         raise werkzeug.exceptions.NotFound()

    #     if 'error' not in qcontext and request.httprequest.method == 'POST':
    #         try:
    #             self.do_signup(qcontext)
    #             return self.web_login(*args, **kw)
    #         except (SignupError, AssertionError), e:
    #             if request.env["res.users"].sudo().search([("login", "=", qcontext.get("login"))]):
    #                 qcontext["error"] = _("Another user is already registered using this email address.")
    #             else:
    #                 _logger.error(e.message)
    #                 qcontext['error'] = _("Could not create a new account.")

    #     return request.render('auth_signup.signup', qcontext)