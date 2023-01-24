import logging
import src.user.repo as repo
from os import environ as env
from src.user.user import User


LOGLEVEL = env.get('LOGLEVEL', 'WARN').upper()
root_logger = logging.getLogger()
handler = root_logger.handlers[0]
root_logger.setLevel(LOGLEVEL)
handler.setFormatter(logging.Formatter('[%(levelname)-8s] %(message)s'))


def validate_auth(event):
    auth_user = repo.find_by_email(event['authUser'])
    if auth_user is None or not auth_user.is_admin:
        raise AuthorizationError('this user cannot perform this operation')


def create_admin_user(email):
    data = {
        'email': email,
        'role': 'ADMIN',
    }
    try:
        new_admin_user = User(**data)
        return repo.save(new_admin_user).asdict()
    except repo.DuplicateKey:
        raise ApplicationError('this user already exists')


def create_user(event, context):
    if repo.is_empty():
        return create_admin_user('authUser')

    validate_auth(event)

    data = {
        'email': event['data']['email'],
        'role': event['data'].get('role'),
    }
    try:
        new_user = User(**data)
        return repo.save(new_user).asdict()
    except repo.DuplicateKey:
        raise ApplicationError('this user already exists')


def list_users(event, context):
    validate_auth(event)
    return {
        "data": [u.asdict() for u in repo.find_all()]
    }


def delete_user(event, context):
    validate_auth(event)
    repo.delete(int(event['userId']))


class ApplicationError(Exception):
    def __init__(self, message):
        super().__init__(f'(ApplicationError) {message}')


class AuthorizationError(Exception):
    def __init__(self, message):
        super().__init__(f'(AuthorizationError) {message}')
