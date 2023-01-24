import boto3
import decimal
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from os import environ as env
from src.user.user import User
from typing import Union, List


dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table(env['USERS_TABLE'])
counters_table = dynamodb.Table(env['COUNTERS_TABLE'])


class DuplicateKey(Exception):
    pass


def is_empty():
    scan = users_table.scan(Limit=1)
    return scan['Count'] == 0


def find_by_id(userId: int) -> Union[User, None]:
    result = users_table.get_item(
        Key={'id': userId}
    )
    if 'Item' in result:
        return User(**(result['Item']))


def find_by_email(email: str) -> Union[User, None]:
    result = users_table.query(
        IndexName='Email-index',
        KeyConditionExpression=Key('email').eq(email),
    )
    if result['Count'] > 0:
        return User(**result['Items'][0])


def find_all() -> List[User]:
    scan = users_table.scan()
    users = [User(**u) for u in scan['Items']]
    return sorted(users, key=lambda u: u.id)


def save(new_user: User) -> User:
    new_user.id = new_user_id()
    try:
        dynamodb.meta.client.transact_write_items(
                TransactItems=[
                    {
                        "Put": {
                            "TableName": env['USERS_TABLE'],
                            "Item": {
                                "id": new_user.id,
                                "email": new_user.email,
                                "role": new_user.role,
                                },
                            "ConditionExpression": "attribute_not_exists(id)"
                        },
                    },
                    {
                        "Put": {
                            "TableName": env['UNIQUES_TABLE'],
                            "Item": {
                                "value": new_user.email,
                                "type": "email",
                            },
                            "ConditionExpression": "attribute_not_exists(#type)",
                            "ExpressionAttributeNames": {"#type": "type"},
                        },
                    },
                ]
            )
    except ClientError as e:
        if e.response['Error']['Code'] == 'TransactionCanceledException':
            raise DuplicateKey
        raise e
    return new_user


def delete(userId: int) -> None:
    user = find_by_id(userId)
    if user is None:
        return
    dynamodb.meta.client.transact_write_items(
            TransactItems=[
                {
                    "Delete": {
                        "TableName": env['USERS_TABLE'],
                        "Key": {"id": userId},
                    },
                },
                {
                    "Delete": {
                        "TableName": env['UNIQUES_TABLE'],
                        "Key": {
                            "value": user.email,
                            "type": "email",
                            },
                        },
                },
            ]
        )


def new_user_id():
    try:
        response = counters_table.update_item(
            Key={
                'name': 'userId'
            },
            UpdateExpression="set #value = #value + :inc",
            ExpressionAttributeNames={"#value": "value"},
            ReturnValues='UPDATED_OLD',
            ConditionExpression=Attr('name').exists(),
            ExpressionAttributeValues={
                ':inc': decimal.Decimal(1)
            },
        )
        return response['Attributes']['value']
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return create_user_id_counter()
        raise e


def create_user_id_counter():
    initial_value = 1
    counters_table.put_item(
        Item={
            'name': 'userId',
            'value': initial_value
        }
    )
    return initial_value
