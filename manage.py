#!/usr/bin/env python
from flask_script import Server, Manager, Shell
from app import main  # , #  db_session, engine


manager = Manager(main.app)
manager.add_command('runserver', Server())
manager.add_command('shell', Shell(make_context=lambda: {
    'app': main.app,
    'db_session': main.db_session
}))


@manager.command
def syncdb():
    import app.models
    import social_flask_sqlalchemy.models
    app.models.Base.metadata.create_all(main.engine)
    social_flask_sqlalchemy.models.PSABase.metadata.create_all(main.engine)

if __name__ == '__main__':
    manager.run()
