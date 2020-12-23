import cyclone.web
import sys
import redis

from twisted.internet import reactor
from twisted.python import log

DB = redis.Redis(host='localhost', port=32768, db=0)
DB_VAL = 1337

class LoginHandler(cyclone.web.RequestHandler):
    def get_real_session(self, code):
        global DB
        try:
            return DB.get(code)
        except:
            raise cyclone.web.HTTPError(401)
    
    def get_session(self, code):
        return self.get_real_session(code)
        
    
    def get(self):
        code = int(self.get_argument("code"))
        val = self.get_session(code).decode("utf-8")
        self.set_secure_cookie("password", val)
        self.redirect("/")


class MainHandler(cyclone.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("password")

    def get(self):
        if not self.current_user:
            self.write('<html><body><form action="/" method="post">'
                   '<input type="text" name="password">'
                   '<input type="submit" value="Submit">'
                   '</form></body></html>')
        else:
            password = cyclone.escape.xhtml_escape(self.current_user)
            self.write("Password was: " + password)
    def post(self):
        global DB_VAL
        global DB

        DB.set(DB_VAL, self.get_argument('password'))
        self.redirect("/login?code="+str(DB_VAL))


if __name__ == "__main__":
    application = cyclone.web.Application([
        (r"/", MainHandler),
        (r"/login.*", LoginHandler)
    ], cookie_secret="deadbeefcafefeedface")

    log.startLogging(sys.stdout)
    reactor.listenTCP(8888, application)
    reactor.run()
