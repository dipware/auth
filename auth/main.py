import asyncio
import tornado.web
from jinja2 import Environment, PackageLoader, select_autoescape
import auth.config as CONFIG
from auth.handlers.authenticate import AuthenticationHandler
from auth.handlers.register import RegistrationHandler

def make_app(register_template, login_template):
    return tornado.web.Application([
        (r'/register', RegistrationHandler, {'template': register_template},),
        (r'/register/(?P<action>.*)', RegistrationHandler, {'template': register_template},),
        (r'/login', AuthenticationHandler, {'template': login_template},),
        (r'/login/(?P<action>.*)', AuthenticationHandler, {'template': login_template},),
    ], autoreload = True)

async def main():
    env = Environment(
        loader=PackageLoader('main'),
        autoescape=select_autoescape()
    )
    register_template = env.get_template('register.html')
    login_template = env.get_template('login.html')
    app = make_app(register_template, login_template)
    app.listen(CONFIG.PORT)
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())