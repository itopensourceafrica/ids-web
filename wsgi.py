"""Point d'entrée WSGI pour gunicorn / uwsgi / waitress.

Démarre les 4 modules démons en arrière-plan puis expose l'app Flask.
"""

from app import app, _start_modules

# Démarrer les démons IDS (Module 1, 2, 3, 4, 5)
_start_modules()

# L'app Flask est exposée comme 'application' (convention WSGI) et 'app'
application = app
