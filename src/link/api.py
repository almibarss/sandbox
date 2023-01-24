import logging
import src.link.repo as link_repo
import src.user.repo as user_repo
from os import environ as env
from src.link.link import Link


LOGLEVEL = env.get('LOGLEVEL', 'WARN').upper()
root_logger = logging.getLogger()
handler = root_logger.handlers[0]
root_logger.setLevel(LOGLEVEL)
handler.setFormatter(logging.Formatter('[%(levelname)-8s] %(message)s'))


def validate_auth(event):
    auth_user = event['authUser']
    if is_test_user(auth_user):
        return
    if user_repo.find_by_email(auth_user) is None:
        raise AuthorizationError(f'access denied for user {auth_user}')


def is_test_user(user_email):
    return user_email.endswith("@migueli.to")


def get_base_url():
    return f"https://{env['BUCKET_NAME']}/"


def with_url(link):
    return {'url': f'{get_base_url()}{link.backhalf}', **link.asdict()}


def get_info(event, context):
    return {
        'base_url': get_base_url()
    }


def create_link(event, context):
    validate_auth(event)
    data = {
        'origin': event['data']['origin'],
        'backhalf': event['data'].get('backhalf'),
        'user': event['authUser']
    }
    try:
        u = Link(**data)
        return with_url(link_repo.save(u))
    except link_repo.DuplicateKey:
        raise ApplicationError('Backhalf is already taken')


def list_links(event, context):
    validate_auth(event)
    return {
        "data": [with_url(link) for link in link_repo.find_by_user(event['authUser'])]
    }


def delete_link(event, context):
    validate_auth(event)
    data = {
        'user': event['authUser'],
        'backhalf': event['backhalf'],
    }
    try:
        link_repo.delete(**data)
    except link_repo.KeyNotFound:
        raise AuthorizationError('this link cannot be deleted by this user')


def delete_all(event, context):
    validate_auth(event)
    link_repo.delete_all_by_user(event['authUser'])


def edit_link(event, context):
    validate_auth(event)
    backhalf, authUser, data = event.values()
    try:
        return with_url(link_repo.update(backhalf=backhalf, user=authUser, data=data))
    except link_repo.KeyNotFound:
        raise AuthorizationError('this link cannot be edited by this user')
    except link_repo.DuplicateKey:
        raise ApplicationError('Backhalf is already taken')


class ApplicationError(Exception):
    def __init__(self, message):
        super().__init__(f'(ApplicationError) {message}')


class AuthorizationError(Exception):
    def __init__(self, message):
        super().__init__(f'(AuthorizationError) {message}')
