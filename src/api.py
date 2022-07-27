import logging
import src.repo as repo

from os import environ as env
from src.link import Link


LOGLEVEL = env.get('LOGLEVEL', 'WARN').upper()
root_logger = logging.getLogger()
handler = root_logger.handlers[0]
root_logger.setLevel(LOGLEVEL)
handler.setFormatter(logging.Formatter('[%(levelname)-8s] %(message)s'))


def get_base_url():
    return f"https://{env['BUCKET_NAME']}/"


def with_url(link):
    return {'url': f'{get_base_url()}{link.backhalf}', **link.asdict()}


def get_info(event, context):
    return {
        'base_url': get_base_url()
    }


def create_link(event, context):
    data = {
        'origin': event['data']['origin'],
        'backhalf': event['data'].get('backhalf'),
        'user': event.get('user')
    }
    try:
        u = Link(**data)
        return with_url(repo.save(u))
    except repo.DuplicateKey:
        raise ApplicationError('Backhalf is already taken')


def list_links(event, context):
    return {
        "data": [with_url(link) for link in repo.find_by_user(event['user'])]
    }


def delete_link(event, context):
    data = {
        'user': event['user'],
        'backhalf': event['backhalf'],
    }
    try:
        repo.delete(**data)
    except repo.KeyNotFound:
        raise AuthorizationError('forbidden')


def delete_all(event, context):
    repo.delete_all_by_user(event['user'])


def edit_link(event, context):
    backhalf, user, data = event.values()
    try:
        return with_url(repo.update(backhalf=backhalf, user=user, data=data))
    except repo.KeyNotFound:
        raise AuthorizationError('forbidden')
    except repo.DuplicateKey:
        raise ApplicationError('Backhalf is already taken')


class ApplicationError(Exception):
    def __init__(self, message):
        super().__init__(f'(ApplicationError) {message}')


class AuthorizationError(Exception):
    def __init__(self, message):
        super().__init__(f'(AuthorizationError) {message}')
