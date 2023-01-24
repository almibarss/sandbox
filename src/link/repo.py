import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from datetime import datetime
from os import environ as env
from src.link.link import Link
from typing import Dict, List


bucket = boto3.resource('s3').Bucket(env['BUCKET_NAME'])
table = boto3.resource('dynamodb').Table(env['LINKS_TABLE'])


class DuplicateKey(Exception):
    pass


class KeyNotFound(Exception):
    pass


def is_taken(backhalf):
    try:
        bucket.Object(backhalf).load()
        return True
    except ClientError as ex:
        if ex.response['Error']['Code'] == '404':
            return False
        raise ex


def find_by_user(user: str) -> List[Link]:
    result = table.query(
        IndexName='User-index',
        KeyConditionExpression=Key('user').eq(user),
    )
    return [Link(**i) for i in result['Items']]


def save(new_link: Link, overwrite=False) -> Link:
    try:
        params = {
            'Item': new_link.asdict()
        }
        if not overwrite:
            params['ConditionExpression'] = Attr('origin').not_exists()
        table.put_item(**params)
        bucket.Object(new_link.backhalf).put(
                WebsiteRedirectLocation=new_link.origin,
                ACL='public-read'
        )
        return new_link
    except ClientError as ex:
        if ex.response['Error']['Code'] == 'ConditionalCheckFailedException':
            raise DuplicateKey
        raise ex


def delete(backhalf: str, user: str) -> None:
    try:
        table.delete_item(
            Key={
                'backhalf': backhalf
            },
            ConditionExpression=Attr('user').eq(user)
        )
        bucket.Object(backhalf).delete()
    except ClientError as ex:
        if ex.response['Error']['Code'] == 'ConditionalCheckFailedException':
            raise KeyNotFound
        raise ex


def delete_all_by_user(user: str) -> None:
    scan = table.scan(FilterExpression=Attr("user").eq(user))
    with table.batch_writer() as batch:
        for each in scan['Items']:
            batch.delete_item(
                Key={
                    'backhalf': each['backhalf']
                }
            )
            bucket.Object(each['backhalf']).delete()


def update(backhalf: str, user: str, data: Dict) -> Link:
    updated_link = get(backhalf)
    if updated_link.user != user:
        raise KeyNotFound
    try:
        if 'backhalf' in data:
            updated_link.backhalf = data['backhalf']
        if 'origin' in data:
            updated_link.origin = data['origin']
        updated_link.updated_at = str(datetime.now())

        save(updated_link, overwrite=('backhalf' not in data))

        if 'backhalf' in data:
            delete(backhalf, user)
        return updated_link
    except ClientError as ex:
        if ex.response['Error']['Code'] == 'ConditionalCheckFailedException':
            raise DuplicateKey


def get(backhalf: str) -> Link:
    i = table.get_item(
        Key={
            'backhalf': backhalf
        }
    )
    if 'Item' not in i:
        raise KeyNotFound
    return Link(**(i['Item']))
