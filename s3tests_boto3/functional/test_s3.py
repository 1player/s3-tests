import boto3
import botocore.session
from botocore.exceptions import ClientError
from botocore.exceptions import ParamValidationError
from nose.tools import eq_ as eq
from nose.tools import nottest
from nose.plugins.attrib import attr
from nose.plugins.skip import SkipTest
import isodate
import email.utils
import datetime
import threading
import re
import pytz
from collections import OrderedDict
import requests
import json
import base64
import hmac
import hashlib
import xml.etree.ElementTree as ET
import time
import operator
import nose
import os
import string
import random
import socket
import ssl
from collections import namedtuple

from email.header import decode_header

from .utils import assert_raises
from .utils import generate_random
from .utils import _get_status_and_error_code
from .utils import _get_status

from .policy import Policy, Statement, make_json_policy

from . import (
    get_client,
    get_prefix,
    get_unauthenticated_client,
    get_bad_auth_client,
    get_v2_client,
    get_new_bucket,
    get_new_bucket_name,
    get_new_bucket_resource,
    get_config_is_secure,
    get_config_host,
    get_config_port,
    get_config_endpoint,
    get_main_aws_access_key,
    get_main_aws_secret_key,
    get_main_display_name,
    get_main_user_id,
    get_main_email,
    get_main_api_name,
    get_alt_aws_access_key,
    get_alt_aws_secret_key,
    get_alt_display_name,
    get_alt_user_id,
    get_alt_email,
    get_alt_client,
    get_tenant_client,
    get_tenant_iam_client,
    get_tenant_user_id,
    get_buckets_list,
    get_objects_list,
    get_main_kms_keyid,
    get_secondary_kms_keyid,
    get_svc_client,
    nuke_prefixed_buckets,
    )


def _bucket_is_empty(bucket):
    is_empty = True
    for obj in bucket.objects.all():
        is_empty = False
        break
    return is_empty

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='empty buckets return no contents')
def test_bucket_list_empty():
    bucket = get_new_bucket_resource()
    is_empty = _bucket_is_empty(bucket)
    eq(is_empty, True)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='distinct buckets have different contents')
def test_bucket_list_distinct():
    bucket1 = get_new_bucket_resource()
    bucket2 = get_new_bucket_resource()
    obj = bucket1.put_object(Body='str', Key='asdf')
    is_empty = _bucket_is_empty(bucket2)
    eq(is_empty, True)

def _create_objects(bucket=None, bucket_name=None, keys=[]):
    """
    Populate a (specified or new) bucket with objects with
    specified names (and contents identical to their names).
    """
    if bucket_name is None:
        bucket_name = get_new_bucket_name()
    if bucket is None:
        bucket = get_new_bucket_resource(name=bucket_name)

    for key in keys:
        obj = bucket.put_object(Body=key, Key=key)

    return bucket_name

def _get_keys(response):
    """
    return lists of strings that are the keys from a client.list_objects() response
    """
    keys = []
    if 'Contents' in response:
        objects_list = response['Contents']
        keys = [obj['Key'] for obj in objects_list]
    return keys

def _get_prefixes(response):
    """
    return lists of strings that are prefixes from a client.list_objects() response
    """
    prefixes = []
    if 'CommonPrefixes' in response:
        prefix_list = response['CommonPrefixes']
        prefixes = [prefix['Prefix'] for prefix in prefix_list]
    return prefixes

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='pagination w/max_keys=2, no marker')
def test_bucket_list_many():
    bucket_name = _create_objects(keys=['foo', 'bar', 'baz'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, MaxKeys=2)
    keys = _get_keys(response)
    eq(len(keys), 2)
    eq(keys, ['bar', 'baz'])
    eq(response['IsTruncated'], True)

    response = client.list_objects(Bucket=bucket_name, Marker='baz',MaxKeys=2)
    keys = _get_keys(response)
    eq(len(keys), 1)
    eq(response['IsTruncated'], False)
    eq(keys, ['foo'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='pagination w/max_keys=2, no marker')
@attr('list-objects-v2')
def test_bucket_listv2_many():
    bucket_name = _create_objects(keys=['foo', 'bar', 'baz'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=2)
    keys = _get_keys(response)
    eq(len(keys), 2)
    eq(keys, ['bar', 'baz'])
    eq(response['IsTruncated'], True)

    response = client.list_objects_v2(Bucket=bucket_name, StartAfter='baz',MaxKeys=2)
    keys = _get_keys(response)
    eq(len(keys), 1)
    eq(response['IsTruncated'], False)
    eq(keys, ['foo'])


@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='keycount in listobjectsv2')
@attr('list-objects-v2')
def test_basic_key_count():
    client = get_client()
    bucket_names = []
    bucket_name = get_new_bucket_name()
    client.create_bucket(Bucket=bucket_name)
    for j in range(5):
            client.put_object(Bucket=bucket_name, Key=str(j))
    response1 = client.list_objects_v2(Bucket=bucket_name)
    eq(response1['KeyCount'], 5)



@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefixes in multi-component object names')
def test_bucket_list_delimiter_basic():
    bucket_name = _create_objects(keys=['foo/bar', 'foo/bar/xyzzy', 'quux/thud', 'asdf'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='/')
    eq(response['Delimiter'], '/')
    keys = _get_keys(response)
    eq(keys, ['asdf'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    eq(prefixes, ['foo/', 'quux/'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefixes in multi-component object names')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_basic():
    bucket_name = _create_objects(keys=['foo/bar', 'foo/bar/xyzzy', 'quux/thud', 'asdf'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='/')
    eq(response['Delimiter'], '/')
    keys = _get_keys(response)
    eq(keys, ['asdf'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    eq(prefixes, ['foo/', 'quux/'])

def validate_bucket_list(bucket_name, prefix, delimiter, marker, max_keys,
                         is_truncated, check_objs, check_prefixes, next_marker):
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter=delimiter, Marker=marker, MaxKeys=max_keys, Prefix=prefix)
    eq(response['IsTruncated'], is_truncated)
    if 'NextMarker' not in response:
        response['NextMarker'] = None
    eq(response['NextMarker'], next_marker)

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)

    eq(len(keys), len(check_objs))
    eq(len(prefixes), len(check_prefixes))
    eq(keys, check_objs)
    eq(prefixes, check_prefixes)

    return response['NextMarker']

def validate_bucket_listv2(bucket_name, prefix, delimiter, continuation_token, max_keys,
                         is_truncated, check_objs, check_prefixes, last=False):
    client = get_client()

    params = dict(Bucket=bucket_name, Delimiter=delimiter, MaxKeys=max_keys, Prefix=prefix)
    if continuation_token is not None:
        params['ContinuationToken'] = continuation_token
    else:
        params['StartAfter'] = ''
    response = client.list_objects_v2(**params)
    eq(response['IsTruncated'], is_truncated)
    if 'NextContinuationToken' not in response:
        response['NextContinuationToken'] = None
    if last:
        eq(response['NextContinuationToken'], None)


    keys = _get_keys(response)
    prefixes = _get_prefixes(response)

    eq(len(keys), len(check_objs))
    eq(len(prefixes), len(check_prefixes))
    eq(keys, check_objs)
    eq(prefixes, check_prefixes)

    return response['NextContinuationToken']

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefixes in multi-component object names')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_prefix():
    bucket_name = _create_objects(keys=['asdf', 'boo/bar', 'boo/baz/xyzzy', 'cquux/thud', 'cquux/bla'])

    delim = '/'
    continuation_token = ''
    prefix = ''

    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, None, 1, True, ['asdf'], [])
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token, 1, True, [], ['boo/'])
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token, 1, False, [], ['cquux/'], last=True)

    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, None, 2, True, ['asdf'], ['boo/'])
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token, 2, False, [], ['cquux/'], last=True)

    prefix = 'boo/'

    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, None, 1, True, ['boo/bar'], [])
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token, 1, False, [], ['boo/baz/'], last=True)

    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, None, 2, False, ['boo/bar'], ['boo/baz/'], last=True)


@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefix and delimiter handling when object ends with delimiter')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_prefix_ends_with_delimiter():
    bucket_name = _create_objects(keys=['asdf/'])
    validate_bucket_listv2(bucket_name, 'asdf/', '/', None, 1000, False, ['asdf/'], [], last=True)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefix and delimiter handling when object ends with delimiter')
def test_bucket_list_delimiter_prefix_ends_with_delimiter():
    bucket_name = _create_objects(keys=['asdf/'])
    validate_bucket_list(bucket_name, 'asdf/', '/', '', 1000, False, ['asdf/'], [], None)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='non-slash delimiter characters')
def test_bucket_list_delimiter_alt():
    bucket_name = _create_objects(keys=['bar', 'baz', 'cab', 'foo'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='a')
    eq(response['Delimiter'], 'a')

    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    # bar, baz, and cab should be broken up by the 'a' delimiters
    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    eq(prefixes, ['ba', 'ca'])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='non-slash delimiter characters')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_alt():
    bucket_name = _create_objects(keys=['bar', 'baz', 'cab', 'foo'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='a')
    eq(response['Delimiter'], 'a')

    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    # bar, baz, and cab should be broken up by the 'a' delimiters
    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    eq(prefixes, ['ba', 'ca'])


@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefixes starting with underscore')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_prefix_underscore():
    bucket_name = _create_objects(keys=['_obj1_','_under1/bar', '_under1/baz/xyzzy', '_under2/thud', '_under2/bla'])

    delim = '/'
    continuation_token = ''
    prefix = ''
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, None, 1, True, ['_obj1_'], [])
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token , 1, True, [], ['_under1/'])
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token , 1, False, [], ['_under2/'], last=True)

    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, None, 2, True, ['_obj1_'], ['_under1/'])
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token , 2, False, [], ['_under2/'], last=True)

    prefix = '_under1/'

    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, None, 1, True, ['_under1/bar'], [])
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token , 1, False, [], ['_under1/baz/'], last=True)

    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, None, 2, False, ['_under1/bar'], ['_under1/baz/'], last=True)


@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='percentage delimiter characters')
def test_bucket_list_delimiter_percentage():
    bucket_name = _create_objects(keys=['b%ar', 'b%az', 'c%ab', 'foo'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='%')
    eq(response['Delimiter'], '%')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b%', 'c%'])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='percentage delimiter characters')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_percentage():
    bucket_name = _create_objects(keys=['b%ar', 'b%az', 'c%ab', 'foo'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='%')
    eq(response['Delimiter'], '%')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b%', 'c%'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='whitespace delimiter characters')
def test_bucket_list_delimiter_whitespace():
    bucket_name = _create_objects(keys=['b ar', 'b az', 'c ab', 'foo'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter=' ')
    eq(response['Delimiter'], ' ')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b ', 'c '])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='whitespace delimiter characters')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_whitespace():
    bucket_name = _create_objects(keys=['b ar', 'b az', 'c ab', 'foo'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter=' ')
    eq(response['Delimiter'], ' ')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b ', 'c '])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='dot delimiter characters')
def test_bucket_list_delimiter_dot():
    bucket_name = _create_objects(keys=['b.ar', 'b.az', 'c.ab', 'foo'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='.')
    eq(response['Delimiter'], '.')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b.', 'c.'])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='dot delimiter characters')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_dot():
    bucket_name = _create_objects(keys=['b.ar', 'b.az', 'c.ab', 'foo'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='.')
    eq(response['Delimiter'], '.')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b.', 'c.'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='non-printable delimiter can be specified')
def test_bucket_list_delimiter_unreadable():
    key_names=['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='\x0a')
    eq(response['Delimiter'], '\x0a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='non-printable delimiter can be specified')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_unreadable():
    key_names=['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='\x0a')
    eq(response['Delimiter'], '\x0a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='empty delimiter can be specified')
def test_bucket_list_delimiter_empty():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='')
    # putting an empty value into Delimiter will not return a value in the response
    eq('Delimiter' in response, False)

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='empty delimiter can be specified')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_empty():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='')
    # putting an empty value into Delimiter will not return a value in the response
    eq('Delimiter' in response, False)

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='unspecified delimiter defaults to none')
def test_bucket_list_delimiter_none():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name)
    # putting an empty value into Delimiter will not return a value in the response
    eq('Delimiter' in response, False)

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='unspecified delimiter defaults to none')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_none():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name)
    # putting an empty value into Delimiter will not return a value in the response
    eq('Delimiter' in response, False)

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr('list-objects-v2')
def test_bucket_listv2_fetchowner_notempty():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, FetchOwner=True)
    objs_list = response['Contents']
    eq('Owner' in objs_list[0], True)

@attr('list-objects-v2')
def test_bucket_listv2_fetchowner_defaultempty():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name)
    objs_list = response['Contents']
    eq('Owner' in objs_list[0], False)

@attr('list-objects-v2')
def test_bucket_listv2_fetchowner_empty():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, FetchOwner= False)
    objs_list = response['Contents']
    eq('Owner' in objs_list[0], False)




@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='unused delimiter is not found')
def test_bucket_list_delimiter_not_exist():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='/')
    # putting an empty value into Delimiter will not return a value in the response
    eq(response['Delimiter'], '/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='unused delimiter is not found')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_not_exist():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='/')
    # putting an empty value into Delimiter will not return a value in the response
    eq(response['Delimiter'], '/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])


@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='list with delimiter not skip special keys')
def test_bucket_list_delimiter_not_skip_special():
    key_names = ['0/'] + ['0/%s' % i for i in range(1000, 1999)]
    key_names2 = ['1999', '1999#', '1999+', '2000']
    key_names += key_names2
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='/')
    eq(response['Delimiter'], '/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names2)
    eq(prefixes, ['0/'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='returns only objects under prefix')
def test_bucket_list_prefix_basic():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='foo/')
    eq(response['Prefix'], 'foo/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['foo/bar', 'foo/baz'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='returns only objects under prefix')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_basic():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='foo/')
    eq(response['Prefix'], 'foo/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['foo/bar', 'foo/baz'])
    eq(prefixes, [])

# just testing that we can do the delimeter and prefix logic on non-slashes
@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='prefixes w/o delimiters')
def test_bucket_list_prefix_alt():
    key_names = ['bar', 'baz', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='ba')
    eq(response['Prefix'], 'ba')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['bar', 'baz'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='prefixes w/o delimiters')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_alt():
    key_names = ['bar', 'baz', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='ba')
    eq(response['Prefix'], 'ba')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['bar', 'baz'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='empty prefix returns everything')
def test_bucket_list_prefix_empty():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='')
    eq(response['Prefix'], '')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='empty prefix returns everything')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_empty():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='')
    eq(response['Prefix'], '')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='unspecified prefix returns everything')
def test_bucket_list_prefix_none():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='')
    eq(response['Prefix'], '')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='unspecified prefix returns everything')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_none():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='')
    eq(response['Prefix'], '')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='nonexistent prefix returns nothing')
def test_bucket_list_prefix_not_exist():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='d')
    eq(response['Prefix'], 'd')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='nonexistent prefix returns nothing')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_not_exist():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='d')
    eq(response['Prefix'], 'd')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='non-printable prefix can be specified')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_unreadable():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='\x0a')
    eq(response['Prefix'], '\x0a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix w/delimiter')
@attr(assertion='returns only objects directly under prefix')
def test_bucket_list_prefix_delimiter_basic():
    key_names = ['foo/bar', 'foo/baz/xyzzy', 'quux/thud', 'asdf']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='/', Prefix='foo/')
    eq(response['Prefix'], 'foo/')
    eq(response['Delimiter'], '/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['foo/bar'])
    eq(prefixes, ['foo/baz/'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list-objects-v2 under prefix w/delimiter')
@attr(assertion='returns only objects directly under prefix')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_delimiter_basic():
    key_names = ['foo/bar', 'foo/baz/xyzzy', 'quux/thud', 'asdf']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='/', Prefix='foo/')
    eq(response['Prefix'], 'foo/')
    eq(response['Delimiter'], '/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['foo/bar'])
    eq(prefixes, ['foo/baz/'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix w/delimiter')
@attr(assertion='non-slash delimiters')
def test_bucket_list_prefix_delimiter_alt():
    key_names = ['bar', 'bazar', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='a', Prefix='ba')
    eq(response['Prefix'], 'ba')
    eq(response['Delimiter'], 'a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['bar'])
    eq(prefixes, ['baza'])

@attr('list-objects-v2')
def test_bucket_listv2_prefix_delimiter_alt():
    key_names = ['bar', 'bazar', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='a', Prefix='ba')
    eq(response['Prefix'], 'ba')
    eq(response['Delimiter'], 'a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['bar'])
    eq(prefixes, ['baza'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix w/delimiter')
@attr(assertion='finds nothing w/unmatched prefix')
def test_bucket_list_prefix_delimiter_prefix_not_exist():
    key_names = ['b/a/r', 'b/a/c', 'b/a/g', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='d', Prefix='/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list-objects-v2 under prefix w/delimiter')
@attr(assertion='finds nothing w/unmatched prefix')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_delimiter_prefix_not_exist():
    key_names = ['b/a/r', 'b/a/c', 'b/a/g', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='d', Prefix='/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix w/delimiter')
@attr(assertion='over-ridden slash ceases to be a delimiter')
def test_bucket_list_prefix_delimiter_delimiter_not_exist():
    key_names = ['b/a/c', 'b/a/g', 'b/a/r', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='z', Prefix='b')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['b/a/c', 'b/a/g', 'b/a/r'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list-objects-v2 under prefix w/delimiter')
@attr(assertion='over-ridden slash ceases to be a delimiter')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_delimiter_delimiter_not_exist():
    key_names = ['b/a/c', 'b/a/g', 'b/a/r', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='z', Prefix='b')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['b/a/c', 'b/a/g', 'b/a/r'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix w/delimiter')
@attr(assertion='finds nothing w/unmatched prefix and delimiter')
def test_bucket_list_prefix_delimiter_prefix_delimiter_not_exist():
    key_names = ['b/a/c', 'b/a/g', 'b/a/r', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='z', Prefix='y')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list-objects-v2 under prefix w/delimiter')
@attr(assertion='finds nothing w/unmatched prefix and delimiter')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_delimiter_prefix_delimiter_not_exist():
    key_names = ['b/a/c', 'b/a/g', 'b/a/r', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='z', Prefix='y')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='pagination w/max_keys=1, marker')
def test_bucket_list_maxkeys_one():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, MaxKeys=1)
    eq(response['IsTruncated'], True)

    keys = _get_keys(response)
    eq(keys, key_names[0:1])

    response = client.list_objects(Bucket=bucket_name, Marker=key_names[0])
    eq(response['IsTruncated'], False)

    keys = _get_keys(response)
    eq(keys, key_names[1:])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='pagination w/max_keys=1, marker')
@attr('list-objects-v2')
def test_bucket_listv2_maxkeys_one():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
    eq(response['IsTruncated'], True)

    keys = _get_keys(response)
    eq(keys, key_names[0:1])

    response = client.list_objects_v2(Bucket=bucket_name, StartAfter=key_names[0])
    eq(response['IsTruncated'], False)

    keys = _get_keys(response)
    eq(keys, key_names[1:])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='pagination w/max_keys=0')
def test_bucket_list_maxkeys_zero():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, MaxKeys=0)

    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='pagination w/max_keys=0')
@attr('list-objects-v2')
def test_bucket_listv2_maxkeys_zero():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=0)

    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='pagination w/o max_keys')
def test_bucket_list_maxkeys_none():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name)
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)
    eq(response['MaxKeys'], 1000)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='pagination w/o max_keys')
@attr('list-objects-v2')
def test_bucket_listv2_maxkeys_none():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name)
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)
    eq(response['MaxKeys'], 1000)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='invalid max_keys')
def test_bucket_list_maxkeys_invalid():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    # adds invalid max keys to url
    # before list_objects is called
    def add_invalid_maxkeys(**kwargs):
        kwargs['params']['url'] += "&max-keys=blah"
    client.meta.events.register('before-call.s3.ListObjects', add_invalid_maxkeys)

    e = assert_raises(ClientError, client.list_objects, Bucket=bucket_name)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidArgument')



@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='no pagination, no marker')
def test_bucket_list_marker_none():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name)
    eq(response['Marker'], '')


@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='no pagination, empty marker')
def test_bucket_list_marker_empty():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Marker='')
    eq(response['Marker'], '')
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list keys with list-objects-v2')
@attr(assertion='no pagination, non-empty continuationtoken')
@attr('list-objects-v2')
def test_bucket_listv2_continuationtoken():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response1 = client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
    next_continuation_token = response1['NextContinuationToken']

    response2 = client.list_objects_v2(Bucket=bucket_name, ContinuationToken=next_continuation_token)
    eq(response2['ContinuationToken'], next_continuation_token)
    eq(response2['IsTruncated'], False)
    key_names2 = ['baz', 'foo', 'quxx']
    keys = _get_keys(response2)
    eq(keys, key_names2)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list keys with list-objects-v2')
@attr(assertion='no pagination, non-empty continuationtoken and startafter')
@attr('list-objects-v2')
def test_bucket_listv2_both_continuationtoken_startafter():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response1 = client.list_objects_v2(Bucket=bucket_name, StartAfter='bar', MaxKeys=1)
    next_continuation_token = response1['NextContinuationToken']

    response2 = client.list_objects_v2(Bucket=bucket_name, StartAfter='bar', ContinuationToken=next_continuation_token)
    eq(response2['ContinuationToken'], next_continuation_token)
    eq(response2['StartAfter'], 'bar')
    eq(response2['IsTruncated'], False)
    key_names2 = ['foo', 'quxx']
    keys = _get_keys(response2)
    eq(keys, key_names2)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='non-printing marker')
def test_bucket_list_marker_unreadable():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Marker='\x0a')
    eq(response['Marker'], '\x0a')
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='non-printing startafter')
@attr('list-objects-v2')
def test_bucket_listv2_startafter_unreadable():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, StartAfter='\x0a')
    eq(response['StartAfter'], '\x0a')
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='marker not-in-list')
def test_bucket_list_marker_not_in_list():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Marker='blah')
    eq(response['Marker'], 'blah')
    keys = _get_keys(response)
    eq(keys, [ 'foo','quxx'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='startafter not-in-list')
@attr('list-objects-v2')
def test_bucket_listv2_startafter_not_in_list():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, StartAfter='blah')
    eq(response['StartAfter'], 'blah')
    keys = _get_keys(response)
    eq(keys, ['foo', 'quxx'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='marker after list')
def test_bucket_list_marker_after_list():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Marker='zzz')
    eq(response['Marker'], 'zzz')
    keys = _get_keys(response)
    eq(response['IsTruncated'], False)
    eq(keys, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='startafter after list')
@attr('list-objects-v2')
def test_bucket_listv2_startafter_after_list():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, StartAfter='zzz')
    eq(response['StartAfter'], 'zzz')
    keys = _get_keys(response)
    eq(response['IsTruncated'], False)
    eq(keys, [])

def _compare_dates(datetime1, datetime2):
    """
    changes ms from datetime1 to 0, compares it to datetime2
    """
    # both times are in datetime format but datetime1 has
    # microseconds and datetime2 does not
    datetime1 = datetime1.replace(microsecond=0)
    eq(datetime1, datetime2)

# amazon is eventually consistent, retry a bit if failed
def check_configure_versioning_retry(bucket_name, status, expected_string):
    client = get_client()

    response = client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'MFADelete': 'Disabled','Status': status})

    read_status = None

    for i in range(5):
        try:
            response = client.get_bucket_versioning(Bucket=bucket_name)
            read_status = response['Status']
        except KeyError:
            read_status = None

        if (expected_string == read_status):
            break

        time.sleep(1)

    eq(expected_string, read_status)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all objects (anonymous)')
@attr(assertion='fails')
def test_bucket_list_objects_anonymous_fail():
    bucket_name = get_new_bucket()

    unauthenticated_client = get_unauthenticated_client()
    e = assert_raises(ClientError, unauthenticated_client.list_objects, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all objects (anonymous) with list-objects-v2')
@attr(assertion='fails')
@attr('list-objects-v2')
def test_bucket_listv2_objects_anonymous_fail():
    bucket_name = get_new_bucket()

    unauthenticated_client = get_unauthenticated_client()
    e = assert_raises(ClientError, unauthenticated_client.list_objects_v2, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='non-existant bucket')
@attr(assertion='fails 404')
def test_bucket_notexist():
    bucket_name = get_new_bucket_name()
    client = get_client()

    e = assert_raises(ClientError, client.list_objects, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='non-existant bucket with list-objects-v2')
@attr(assertion='fails 404')
@attr('list-objects-v2')
def test_bucketv2_notexist():
    bucket_name = get_new_bucket_name()
    client = get_client()

    e = assert_raises(ClientError, client.list_objects_v2, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='bucket')
@attr(method='delete')
@attr(operation='non-existant bucket')
@attr(assertion='fails 404')
def test_bucket_delete_notexist():
    bucket_name = get_new_bucket_name()
    client = get_client()

    e = assert_raises(ClientError, client.delete_bucket, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='bucket')
@attr(method='delete')
@attr(operation='non-empty bucket')
@attr(assertion='fails 409')
def test_bucket_delete_nonempty():
    key_names = ['foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    e = assert_raises(ClientError, client.delete_bucket, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 409)
    eq(error_code, 'BucketNotEmpty')

def _do_set_bucket_canned_acl(client, bucket_name, canned_acl, i, results):
    try:
        client.put_bucket_acl(ACL=canned_acl, Bucket=bucket_name)
        results[i] = True
    except:
        results[i] = False

def _do_set_bucket_canned_acl_concurrent(client, bucket_name, canned_acl, num, results):
    t = []
    for i in range(num):
        thr = threading.Thread(target = _do_set_bucket_canned_acl, args=(client, bucket_name, canned_acl, i, results))
        thr.start()
        t.append(thr)
    return t

def _do_wait_completion(t):
    for thr in t:
        thr.join()

@attr(resource='object')
@attr(method='put')
@attr(operation='non-existant bucket')
@attr(assertion='fails 404')
def test_object_write_to_nonexist_bucket():
    key_names = ['foo']
    bucket_name = 'whatchutalkinboutwillis'
    client = get_client()

    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key='foo', Body='foo')

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')


@attr(resource='bucket')
@attr(method='del')
@attr(operation='deleted bucket')
@attr(assertion='fails 404')
def test_bucket_create_delete():
    bucket_name = get_new_bucket()
    client = get_client()
    client.delete_bucket(Bucket=bucket_name)

    e = assert_raises(ClientError, client.delete_bucket, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='object')
@attr(method='get')
@attr(operation='read contents that were never written')
@attr(assertion='fails 404')
def test_object_read_not_exist():
    bucket_name = get_new_bucket()
    client = get_client()

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='bar')

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

http_response = None

def get_http_response(**kwargs):
    global http_response
    http_response = kwargs['http_response'].__dict__

@attr(resource='object')
@attr(method='get')
@attr(operation='read contents that were never written to raise one error response')
@attr(assertion='RequestId appears in the error response')
def test_object_requestid_matches_header_on_error():
    bucket_name = get_new_bucket()
    client = get_client()

    # get http response after failed request
    client.meta.events.register('after-call.s3.GetObject', get_http_response)
    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='bar')

    response_body = http_response['_content']
    resp_body_xml = ET.fromstring(response_body)
    request_id = resp_body_xml.find('.//RequestId').text

    assert request_id is not None
    eq(request_id, e.response['ResponseMetadata']['RequestId'])

def _make_objs_dict(key_names):
    objs_list = []
    for key in key_names:
        obj_dict = {'Key': key}
        objs_list.append(obj_dict)
    objs_dict = {'Objects': objs_list}
    return objs_dict

@attr(resource='object')
@attr(method='post')
@attr(operation='delete multiple objects')
@attr(assertion='deletes multiple objects with a single call')
def test_multi_object_delete():
    key_names = ['key0', 'key1', 'key2']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()
    response = client.list_objects(Bucket=bucket_name)
    eq(len(response['Contents']), 3)

    objs_dict = _make_objs_dict(key_names=key_names)
    response = client.delete_objects(Bucket=bucket_name, Delete=objs_dict)

    eq(len(response['Deleted']), 3)
    assert 'Errors' not in response
    response = client.list_objects(Bucket=bucket_name)
    assert 'Contents' not in response

    response = client.delete_objects(Bucket=bucket_name, Delete=objs_dict)
    eq(len(response['Deleted']), 3)
    assert 'Errors' not in response
    response = client.list_objects(Bucket=bucket_name)
    assert 'Contents' not in response

@attr(resource='object')
@attr(method='post')
@attr(operation='delete multiple objects with list-objects-v2')
@attr(assertion='deletes multiple objects with a single call')
@attr('list-objects-v2')
def test_multi_objectv2_delete():
    key_names = ['key0', 'key1', 'key2']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()
    response = client.list_objects_v2(Bucket=bucket_name)
    eq(len(response['Contents']), 3)

    objs_dict = _make_objs_dict(key_names=key_names)
    response = client.delete_objects(Bucket=bucket_name, Delete=objs_dict)

    eq(len(response['Deleted']), 3)
    assert 'Errors' not in response
    response = client.list_objects_v2(Bucket=bucket_name)
    assert 'Contents' not in response

    response = client.delete_objects(Bucket=bucket_name, Delete=objs_dict)
    eq(len(response['Deleted']), 3)
    assert 'Errors' not in response
    response = client.list_objects_v2(Bucket=bucket_name)
    assert 'Contents' not in response

@attr(resource='object')
@attr(method='put')
@attr(operation='write zero-byte key')
@attr(assertion='correct content length')
def test_object_head_zero_bytes():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='')

    response = client.head_object(Bucket=bucket_name, Key='foo')
    eq(response['ContentLength'], 0)

@attr(resource='object')
@attr(method='put')
@attr(operation='write key')
@attr(assertion='correct etag')
def test_object_write_check_etag():
    bucket_name = get_new_bucket()
    client = get_client()
    response = client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)
    eq(response['ETag'], '"37b51d194a7513e45b56f6524f2d51f2"')

@attr(resource='object')
@attr(method='put')
@attr(operation='write key')
@attr(assertion='correct cache control header')
def test_object_write_cache_control():
    bucket_name = get_new_bucket()
    client = get_client()
    cache_control = 'public, max-age=14400'
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar', CacheControl=cache_control)

    response = client.head_object(Bucket=bucket_name, Key='foo')
    eq(response['ResponseMetadata']['HTTPHeaders']['cache-control'], cache_control)

@attr(resource='object')
@attr(method='put')
@attr(operation='write key')
@attr(assertion='correct expires header')
def test_object_write_expires():
    bucket_name = get_new_bucket()
    client = get_client()

    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar', Expires=expires)

    response = client.head_object(Bucket=bucket_name, Key='foo')
    _compare_dates(expires, response['Expires'])

def _get_body(response):
    body = response['Body']
    got = body.read()
    if type(got) is bytes:
        got = got.decode()
    return got

@attr(resource='object')
@attr(method='all')
@attr(operation='complete object life cycle')
@attr(assertion='read back what we wrote and rewrote')
def test_object_write_read_update_read_delete():
    bucket_name = get_new_bucket()
    client = get_client()

    # Write
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    # Read
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')
    # Update
    client.put_object(Bucket=bucket_name, Key='foo', Body='soup')
    # Read
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'soup')
    # Delete
    client.delete_object(Bucket=bucket_name, Key='foo')

def _set_get_metadata(metadata, bucket_name=None):
    """
    create a new bucket new or use an existing
    name to create an object that bucket,
    set the meta1 property to a specified, value,
    and then re-read and return that property
    """
    if bucket_name is None:
        bucket_name = get_new_bucket()

    client = get_client()
    metadata_dict = {'meta1': metadata}
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar', Metadata=metadata_dict)

    response = client.get_object(Bucket=bucket_name, Key='foo')
    return response['Metadata']['meta1']

@attr(resource='object.metadata')
@attr(method='put')
@attr(operation='metadata write/re-read')
@attr(assertion='reread what we wrote')
def test_object_set_get_metadata_none_to_good():
    got = _set_get_metadata('mymeta')
    eq(got, 'mymeta')

@attr(resource='object.metadata')
@attr(method='put')
@attr(operation='metadata write/re-read')
@attr(assertion='write empty value, returns empty value')
def test_object_set_get_metadata_none_to_empty():
    got = _set_get_metadata('')
    eq(got, '')

@attr(resource='object.metadata')
@attr(method='put')
@attr(operation='metadata write/re-write')
@attr(assertion='empty value replaces old')
def test_object_set_get_metadata_overwrite_to_empty():
    bucket_name = get_new_bucket()
    got = _set_get_metadata('oldmeta', bucket_name)
    eq(got, 'oldmeta')
    got = _set_get_metadata('', bucket_name)
    eq(got, '')

def _set_get_metadata_unreadable(metadata, bucket_name=None):
    """
    set and then read back a meta-data value (which presumably
    includes some interesting characters), and return a list
    containing the stored value AND the encoding with which it
    was returned.

    This should return a 400 bad request because the webserver
    rejects the request.
    """
    bucket_name = get_new_bucket()
    client = get_client()
    metadata_dict = {'meta1': metadata}
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key='bar', Metadata=metadata_dict)
    return e

@attr(resource='object.metadata')
@attr(method='put')
@attr(operation='metadata write/re-write')
@attr(assertion='non-UTF-8 values detected, but rejected by webserver')
@attr('fails_strict_rfc2616')
@attr(assertion='fails 400')
def test_object_set_get_non_utf8_metadata():
    metadata = '\x04mymeta'
    e = _set_get_metadata_unreadable(metadata)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400 or 403)

@attr(resource='object.metadata')
@attr(method='put')
@attr(operation='metadata write')
@attr(assertion='non-printing prefixes rejected by webserver')
@attr('fails_strict_rfc2616')
@attr(assertion='fails 400')
def test_object_set_get_metadata_empty_to_unreadable_prefix():
    metadata = '\x04w'
    e = _set_get_metadata_unreadable(metadata)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400 or 403)

@attr(resource='object.metadata')
@attr(method='put')
@attr(operation='metadata write')
@attr(assertion='non-printing suffixes rejected by webserver')
@attr('fails_strict_rfc2616')
@attr(assertion='fails 400')
def test_object_set_get_metadata_empty_to_unreadable_suffix():
    metadata = 'h\x04'
    e = _set_get_metadata_unreadable(metadata)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400 or 403)

@attr(resource='object.metadata')
@attr(method='put')
@attr(operation='metadata write')
@attr(assertion='non-priting in-fixes rejected by webserver')
@attr('fails_strict_rfc2616')
@attr(assertion='fails 400')
def test_object_set_get_metadata_empty_to_unreadable_infix():
    metadata = 'h\x04w'
    e = _set_get_metadata_unreadable(metadata)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400 or 403)

@attr(resource='object')
@attr(method='put')
@attr(operation='data re-write')
@attr(assertion='replaces previous metadata')
def test_object_metadata_replaced_on_put():
    bucket_name = get_new_bucket()
    client = get_client()
    metadata_dict = {'meta1': 'bar'}
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar', Metadata=metadata_dict)

    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    got = response['Metadata']
    eq(got, {})

@attr(resource='object')
@attr(method='put')
@attr(operation='data write from file (w/100-Continue)')
@attr(assertion='succeeds and returns written data')
def test_object_write_file():
    bucket_name = get_new_bucket()
    client = get_client()
    data_str = 'bar'
    data = bytes(data_str, 'utf-8')
    client.put_object(Bucket=bucket_name, Key='foo', Body=data)
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

def _get_post_url(bucket_name):
    endpoint = get_config_endpoint()
    return '{endpoint}/{bucket_name}'.format(endpoint=endpoint, bucket_name=bucket_name)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds and returns written data')
def test_post_object_authenticated_request():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }


    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request, no content-type header')
@attr(assertion='succeeds and returns written data')
def test_post_object_authenticated_no_content_type():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='public-read-write', Bucket=bucket_name)


    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key="foo.txt")
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request, bad access key')
@attr(assertion='fails')
def test_post_object_authenticated_request_bad_access_key():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='public-read-write', Bucket=bucket_name)

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }


    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , 'foo'),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds and returns written data')
def test_post_object_upload_larger_than_chunk():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 5*1024*1024]\
    ]\
    }


    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    foo_string = 'foo' * 1024*1024

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', foo_string)])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, foo_string)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds and returns written data')
def test_post_object_set_key_from_filename():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "${filename}"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('foo.txt', 'bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds with status 204')
def test_post_object_case_insensitive_condition_fields():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bUcKeT": bucket_name},\
    ["StArTs-WiTh", "$KeY", "foo"],\
    {"AcL": "private"},\
    ["StArTs-WiTh", "$CoNtEnT-TyPe", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    foo_string = 'foo' * 1024*1024

    payload = OrderedDict([ ("kEy" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("aCl" , "private"),("signature" , signature),("pOLICy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds with escaped leading $ and returns written data')
def test_post_object_escaped_field_values():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "\$foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='\$foo.txt')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with invalid signature error')
def test_post_object_invalid_signature():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())[::-1]

    payload = OrderedDict([ ("key" , "\$foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with access key does not exist error')
def test_post_object_invalid_access_key():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "\$foo.txt"),("AWSAccessKeyId" , aws_access_key_id[::-1]),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with missing key error')
def test_post_object_no_key_specified():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with missing signature error')
def test_post_object_missing_signature():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with extra input fields policy error')
def test_post_object_missing_policy_condition():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds using starts-with restriction on metadata header')
def test_post_object_user_specified_header():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ["starts-with", "$x-amz-meta-foo",  "bar"]
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('x-amz-meta-foo' , 'barclamp'),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    eq(response['Metadata']['foo'], 'barclamp')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with policy condition failed error due to missing field in POST request')
def test_post_object_request_missing_policy_specified_field():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ["starts-with", "$x-amz-meta-foo",  "bar"]
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with policy expired error')
def test_post_object_expired_policy():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=-6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails using equality restriction on metadata header')
def test_post_object_invalid_request_field_value():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ["eq", "$x-amz-meta-foo",  ""]
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())
    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('x-amz-meta-foo' , 'barclamp'),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with upload size less than minimum allowable error')
def test_post_object_upload_size_below_minimum():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 512, 1000],\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='empty conditions return appropriate error response')
def test_post_object_empty_conditions():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    { }\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Match: the latest ETag')
@attr(assertion='succeeds')
def test_get_object_ifmatch_good():
    bucket_name = get_new_bucket()
    client = get_client()
    response = client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    etag = response['ETag']

    response = client.get_object(Bucket=bucket_name, Key='foo', IfMatch=etag)
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Match: bogus ETag')
@attr(assertion='fails 412')
def test_get_object_ifmatch_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo', IfMatch='"ABCORZ"')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-None-Match: the latest ETag')
@attr(assertion='fails 304')
def test_get_object_ifnonematch_good():
    bucket_name = get_new_bucket()
    client = get_client()
    response = client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    etag = response['ETag']

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo', IfNoneMatch=etag)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 304)
    eq(e.response['Error']['Message'], 'Not Modified')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-None-Match: bogus ETag')
@attr(assertion='succeeds')
def test_get_object_ifnonematch_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo', IfNoneMatch='ABCORZ')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Modified-Since: before')
@attr(assertion='succeeds')
def test_get_object_ifmodifiedsince_good():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo', IfModifiedSince='Sat, 29 Oct 1994 19:43:31 GMT')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Modified-Since: after')
@attr(assertion='fails 304')
def test_get_object_ifmodifiedsince_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    response = client.get_object(Bucket=bucket_name, Key='foo')
    last_modified = str(response['LastModified'])

    last_modified = last_modified.split('+')[0]
    mtime = datetime.datetime.strptime(last_modified, '%Y-%m-%d %H:%M:%S')

    after = mtime + datetime.timedelta(seconds=1)
    after_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", after.timetuple())

    time.sleep(1)

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo', IfModifiedSince=after_str)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 304)
    eq(e.response['Error']['Message'], 'Not Modified')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Unmodified-Since: before')
@attr(assertion='fails 412')
def test_get_object_ifunmodifiedsince_good():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo', IfUnmodifiedSince='Sat, 29 Oct 1994 19:43:31 GMT')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Unmodified-Since: after')
@attr(assertion='succeeds')
def test_get_object_ifunmodifiedsince_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo', IfUnmodifiedSince='Sat, 29 Oct 2100 19:43:31 GMT')
    body = _get_body(response)
    eq(body, 'bar')


@attr(resource='object')
@attr(method='put')
@attr(operation='data re-write w/ If-Match: the latest ETag')
@attr(assertion='replaces previous data and metadata')
@attr('fails_on_aws')
def test_put_object_ifmatch_good():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    etag = response['ETag'].replace('"', '')

    # pass in custom header 'If-Match' before PutObject call
    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': etag}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    response = client.put_object(Bucket=bucket_name,Key='foo', Body='zar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'zar')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Match: bogus ETag')
@attr(assertion='fails 412')
def test_put_object_ifmatch_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    # pass in custom header 'If-Match' before PutObject call
    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': '"ABCORZ"'}))
    client.meta.events.register('before-call.s3.PutObject', lf)

    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key='foo', Body='zar')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='put')
@attr(operation='overwrite existing object w/ If-Match: *')
@attr(assertion='replaces previous data and metadata')
@attr('fails_on_aws')
def test_put_object_ifmatch_overwrite_existed_good():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': '*'}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    response = client.put_object(Bucket=bucket_name,Key='foo', Body='zar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'zar')

def _setup_bucket_object_acl(bucket_acl, object_acl):
    """
    add a foo key, and specified key and bucket acls to
    a (new or existing) bucket.
    """
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL=bucket_acl, Bucket=bucket_name)
    client.put_object(ACL=object_acl, Bucket=bucket_name, Key='foo')

    return bucket_name

def _setup_bucket_acl(bucket_acl=None):
    """
    set up a new bucket with specified acl
    """
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL=bucket_acl, Bucket=bucket_name)

    return bucket_name

@attr(resource='object')
@attr(method='get')
@attr(operation='deleted object and bucket')
@attr(assertion='fails 404')
def test_object_raw_get_bucket_gone():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()

    client.delete_object(Bucket=bucket_name, Key='foo')
    client.delete_bucket(Bucket=bucket_name)

    unauthenticated_client = get_unauthenticated_client()

    e = assert_raises(ClientError, unauthenticated_client.get_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)

@attr(resource='object')
@attr(method='get')
@attr(operation='deleted object and bucket')
@attr(assertion='fails 404')
def test_object_delete_key_bucket_gone():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()

    client.delete_object(Bucket=bucket_name, Key='foo')
    client.delete_bucket(Bucket=bucket_name)

    unauthenticated_client = get_unauthenticated_client()

    e = assert_raises(ClientError, unauthenticated_client.delete_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)

@attr(resource='object')
@attr(method='get')
@attr(operation='deleted object')
@attr(assertion='fails 404')
def test_object_raw_get_object_gone():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()

    client.delete_object(Bucket=bucket_name, Key='foo')

    unauthenticated_client = get_unauthenticated_client()

    e = assert_raises(ClientError, unauthenticated_client.get_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)

@attr(resource='bucket')
@attr(method='head')
@attr(operation='head bucket')
@attr(assertion='succeeds')
def test_bucket_head():
    bucket_name = get_new_bucket()
    client = get_client()

    response = client.head_bucket(Bucket=bucket_name)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='object.acl')
@attr(method='get')
@attr(operation='unauthenticated on private object')
@attr(assertion='fails 403')
def test_object_raw_get_object_acl():
    bucket_name = _setup_bucket_object_acl('public-read', 'private')

    unauthenticated_client = get_unauthenticated_client()
    e = assert_raises(ClientError, unauthenticated_client.get_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='authenticated on public bucket/object')
@attr(assertion='succeeds')
def test_object_raw_authenticated():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')

    client = get_client()
    response = client.get_object(Bucket=bucket_name, Key='foo')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='object')
@attr(method='get')
@attr(operation='authenticated on private bucket/private object with modified response headers')
@attr(assertion='succeeds')
def test_object_raw_response_headers():
    bucket_name = _setup_bucket_object_acl('private', 'private')

    client = get_client()

    response = client.get_object(Bucket=bucket_name, Key='foo', ResponseCacheControl='no-cache', ResponseContentDisposition='bla', ResponseContentEncoding='aaa', ResponseContentLanguage='esperanto', ResponseContentType='foo/bar', ResponseExpires='123')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)
    eq(response['ResponseMetadata']['HTTPHeaders']['content-type'], 'foo/bar')
    eq(response['ResponseMetadata']['HTTPHeaders']['content-disposition'], 'bla')
    eq(response['ResponseMetadata']['HTTPHeaders']['content-language'], 'esperanto')
    eq(response['ResponseMetadata']['HTTPHeaders']['content-encoding'], 'aaa')
    eq(response['ResponseMetadata']['HTTPHeaders']['cache-control'], 'no-cache')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='authenticated on private bucket/public object')
@attr(assertion='succeeds')
def test_object_raw_authenticated_bucket_acl():
    bucket_name = _setup_bucket_object_acl('private', 'public-read')

    client = get_client()
    response = client.get_object(Bucket=bucket_name, Key='foo')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='authenticated on public bucket/private object')
@attr(assertion='succeeds')
def test_object_raw_authenticated_object_acl():
    bucket_name = _setup_bucket_object_acl('public-read', 'private')

    client = get_client()
    response = client.get_object(Bucket=bucket_name, Key='foo')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='object')
@attr(method='get')
@attr(operation='authenticated on deleted object and bucket')
@attr(assertion='fails 404')
def test_object_raw_authenticated_bucket_gone():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()

    client.delete_object(Bucket=bucket_name, Key='foo')
    client.delete_bucket(Bucket=bucket_name)

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='object')
@attr(method='get')
@attr(operation='authenticated on deleted object')
@attr(assertion='fails 404')
def test_object_raw_authenticated_object_gone():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()

    client.delete_object(Bucket=bucket_name, Key='foo')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

@attr(resource='object')
@attr(method='get')
@attr(operation='x-amz-expires check not expired')
@attr(assertion='succeeds')
def test_object_raw_get_x_amz_expires_not_expired():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()
    params = {'Bucket': bucket_name, 'Key': 'foo'}

    url = client.generate_presigned_url(ClientMethod='get_object', Params=params, ExpiresIn=100000, HttpMethod='GET')

    res = requests.get(url).__dict__
    eq(res['status_code'], 200)

@attr(resource='object')
@attr(method='get')
@attr(operation='check x-amz-expires value out of range zero')
@attr(assertion='fails 403')
def test_object_raw_get_x_amz_expires_out_range_zero():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()
    params = {'Bucket': bucket_name, 'Key': 'foo'}

    url = client.generate_presigned_url(ClientMethod='get_object', Params=params, ExpiresIn=0, HttpMethod='GET')

    res = requests.get(url).__dict__
    eq(res['status_code'], 403)

@attr(resource='object')
@attr(method='get')
@attr(operation='check x-amz-expires value out of max range')
@attr(assertion='fails 403')
def test_object_raw_get_x_amz_expires_out_max_range():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()
    params = {'Bucket': bucket_name, 'Key': 'foo'}

    url = client.generate_presigned_url(ClientMethod='get_object', Params=params, ExpiresIn=609901, HttpMethod='GET')

    res = requests.get(url).__dict__
    eq(res['status_code'], 400)

@attr(resource='object')
@attr(method='get')
@attr(operation='check x-amz-expires value out of positive range')
@attr(assertion='succeeds')
def test_object_raw_get_x_amz_expires_out_positive_range():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()
    params = {'Bucket': bucket_name, 'Key': 'foo'}

    url = client.generate_presigned_url(ClientMethod='get_object', Params=params, ExpiresIn=-7, HttpMethod='GET')

    res = requests.get(url).__dict__
    eq(res['status_code'], 400)


@attr(resource='object')
@attr(method='put')
@attr(operation='unauthenticated, no object acls')
@attr(assertion='fails 403')
def test_object_anon_put():
    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='foo')

    unauthenticated_client = get_unauthenticated_client()

    e = assert_raises(ClientError, unauthenticated_client.put_object, Bucket=bucket_name, Key='foo', Body='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

@attr(resource='object')
@attr(method='put')
@attr(operation='authenticated, no object acls')
@attr(assertion='succeeds')
def test_object_put_authenticated():
    bucket_name = get_new_bucket()
    client = get_client()

    response = client.put_object(Bucket=bucket_name, Key='foo', Body='foo')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='object')
@attr(method='put')
@attr(operation='authenticated, no object acls')
@attr(assertion='succeeds')
def test_object_raw_put_authenticated_expired():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo')

    params = {'Bucket': bucket_name, 'Key': 'foo'}
    url = client.generate_presigned_url(ClientMethod='put_object', Params=params, ExpiresIn=-1000, HttpMethod='PUT')

    # params wouldn't take a 'Body' parameter so we're passing it in here
    res = requests.put(url,data="foo").__dict__
    eq(res['status_code'], 400)

def check_bad_bucket_name(bucket_name):
    """
    Attempt to create a bucket with a specified name, and confirm
    that the request fails because of an invalid bucket name.
    """
    client = get_client()
    e = assert_raises(ClientError, client.create_bucket, Bucket=bucket_name)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')


# AWS does not enforce all documented bucket restrictions.
# http://docs.amazonwebservices.com/AmazonS3/2006-03-01/dev/index.html?BucketRestrictions.html
@attr('fails_on_aws')
# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='name begins with underscore')
@attr(assertion='fails with subdomain: 400')
def test_bucket_create_naming_bad_starts_nonalpha():
    bucket_name = get_new_bucket_name()
    check_bad_bucket_name('_' + bucket_name)

def check_invalid_bucketname(invalid_name):
    """
    Send a create bucket_request with an invalid bucket name
    that will bypass the ParamValidationError that would be raised
    if the invalid bucket name that was passed in normally.
    This function returns the status and error code from the failure
    """
    client = get_client()
    valid_bucket_name = get_new_bucket_name()
    def replace_bucketname_from_url(**kwargs):
        url = kwargs['params']['url']
        new_url = url.replace(valid_bucket_name, invalid_name)
        kwargs['params']['url'] = new_url
    client.meta.events.register('before-call.s3.CreateBucket', replace_bucketname_from_url)
    e = assert_raises(ClientError, client.create_bucket, Bucket=invalid_name)
    status, error_code = _get_status_and_error_code(e.response)
    return (status, error_code)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='short (one character) name')
@attr(assertion='fails 400')
def test_bucket_create_naming_bad_short_one():
    check_bad_bucket_name('a')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='short (two character) name')
@attr(assertion='fails 400')
def test_bucket_create_naming_bad_short_two():
    check_bad_bucket_name('aa')

def check_good_bucket_name(name, _prefix=None):
    """
    Attempt to create a bucket with a specified name
    and (specified or default) prefix, returning the
    results of that effort.
    """
    # tests using this with the default prefix must *not* rely on
    # being able to set the initial character, or exceed the max len

    # tests using this with a custom prefix are responsible for doing
    # their own setup/teardown nukes, with their custom prefix; this
    # should be very rare
    if _prefix is None:
        _prefix = get_prefix()
    bucket_name = '{prefix}{name}'.format(
            prefix=_prefix,
            name=name,
            )
    client = get_client()
    response = client.create_bucket(Bucket=bucket_name)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

def _test_bucket_create_naming_good_long(length):
    """
    Attempt to create a bucket whose name (including the
    prefix) is of a specified length.
    """
    # tests using this with the default prefix must *not* rely on
    # being able to set the initial character, or exceed the max len

    # tests using this with a custom prefix are responsible for doing
    # their own setup/teardown nukes, with their custom prefix; this
    # should be very rare
    prefix = get_new_bucket_name()
    assert len(prefix) < 63
    num = length - len(prefix)
    name=num*'a'

    bucket_name = '{prefix}{name}'.format(
            prefix=prefix,
            name=name,
            )
    client = get_client()
    response = client.create_bucket(Bucket=bucket_name)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/60 byte name')
@attr(assertion='fails with subdomain')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_good_long_60():
    _test_bucket_create_naming_good_long(60)

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/61 byte name')
@attr(assertion='fails with subdomain')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_good_long_61():
    _test_bucket_create_naming_good_long(61)

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/62 byte name')
@attr(assertion='fails with subdomain')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_good_long_62():
    _test_bucket_create_naming_good_long(62)


# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/63 byte name')
@attr(assertion='fails with subdomain')
def test_bucket_create_naming_good_long_63():
    _test_bucket_create_naming_good_long(63)


# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='get')
@attr(operation='list w/61 byte name')
@attr(assertion='fails with subdomain')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_list_long_name():
    prefix = get_new_bucket_name()
    length = 61
    num = length - len(prefix)
    name=num*'a'

    bucket_name = '{prefix}{name}'.format(
            prefix=prefix,
            name=name,
            )
    bucket = get_new_bucket_resource(name=bucket_name)
    is_empty = _bucket_is_empty(bucket)
    eq(is_empty, True)

# AWS does not enforce all documented bucket restrictions.
# http://docs.amazonwebservices.com/AmazonS3/2006-03-01/dev/index.html?BucketRestrictions.html
@attr('fails_on_aws')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/ip address for name')
@attr(assertion='fails on aws')
def test_bucket_create_naming_bad_ip():
    check_bad_bucket_name('192.168.5.123')

# test_bucket_create_naming_dns_* are valid but not recommended
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/underscore in name')
@attr(assertion='fails')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_dns_underscore():
    invalid_bucketname = 'foo_bar'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/100 byte name')
@attr(assertion='fails with subdomain')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
def test_bucket_create_naming_dns_long():
    prefix = get_prefix()
    assert len(prefix) < 50
    num = 63 - len(prefix)
    check_good_bucket_name(num * 'a')

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/dash at end of name')
@attr(assertion='fails')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_dns_dash_at_end():
    invalid_bucketname = 'foo-'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')


# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/.. in name')
@attr(assertion='fails')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_dns_dot_dot():
    invalid_bucketname = 'foo..bar'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')


# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/.- in name')
@attr(assertion='fails')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_dns_dot_dash():
    invalid_bucketname = 'foo.-bar'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')


# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/-. in name')
@attr(assertion='fails')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_dns_dash_dot():
    invalid_bucketname = 'foo-.bar'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')

def check_access_denied(fn, *args, **kwargs):
    e = assert_raises(ClientError, fn, *args, **kwargs)
    status = _get_status(e.response)
    eq(status, 403)

def check_grants(got, want):
    """
    Check that grants list in got matches the dictionaries in want,
    in any order.
    """
    eq(len(got), len(want))
    for g, w in zip(got, want):
        w = dict(w)
        g = dict(g)
        eq(g.pop('Permission', None), w['Permission'])
        eq(g['Grantee'].pop('DisplayName', None), w['DisplayName'])
        eq(g['Grantee'].pop('ID', None), w['ID'])
        eq(g['Grantee'].pop('Type', None), w['Type'])
        eq(g['Grantee'].pop('URI', None), w['URI'])
        eq(g['Grantee'].pop('EmailAddress', None), w['EmailAddress'])
        eq(g, {'Grantee': {}})

def add_obj_user_grant(bucket_name, key, grant):
    """
    Adds a grant to the existing grants meant to be passed into
    the AccessControlPolicy argument of put_object_acls for an object
    owned by the main user, not the alt user
    A grant is a dictionary in the form of:
    {u'Grantee': {u'Type': 'type', u'DisplayName': 'name', u'ID': 'id'}, u'Permission': 'PERM'}

    """
    client = get_client()
    main_user_id = get_main_user_id()
    main_display_name = get_main_display_name()

    response = client.get_object_acl(Bucket=bucket_name, Key=key)

    grants = response['Grants']
    grants.append(grant)

    grant = {'Grants': grants, 'Owner': {'DisplayName': main_display_name, 'ID': main_user_id}}

    return grant

@attr(resource='object.acls')
@attr(method='put')
@attr(operation='set write-acp')
@attr(assertion='does not modify other attributes')
def test_object_acl_full_control_verify_attributes():
    bucket_name = get_new_bucket_name()
    main_client = get_client()
    alt_client = get_alt_client()

    main_client.create_bucket(Bucket=bucket_name, ACL='public-read-write')

    header = {'x-amz-foo': 'bar'}
    # lambda to add any header
    add_header = (lambda **kwargs: kwargs['params']['headers'].update(header))

    main_client.meta.events.register('before-call.s3.PutObject', add_header)
    main_client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = main_client.get_object(Bucket=bucket_name, Key='foo')
    content_type = response['ContentType']
    etag = response['ETag']

    alt_user_id = get_alt_user_id()

    grant = {'Grantee': {'ID': alt_user_id, 'Type': 'CanonicalUser' }, 'Permission': 'FULL_CONTROL'}

    grants = add_obj_user_grant(bucket_name, 'foo', grant)

    main_client.put_object_acl(Bucket=bucket_name, Key='foo', AccessControlPolicy=grants)

    response = main_client.get_object(Bucket=bucket_name, Key='foo')
    eq(content_type, response['ContentType'])
    eq(etag, response['ETag'])

@attr(resource='bucket')
@attr(method='ACLs')
@attr(operation='set acl private')
@attr(assertion='a private object can be set to private')
def test_bucket_acl_canned_private_to_private():
    bucket_name = get_new_bucket()
    client = get_client()

    response = client.put_bucket_acl(Bucket=bucket_name, ACL='private')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

def add_bucket_user_grant(bucket_name, grant):
    """
    Adds a grant to the existing grants meant to be passed into
    the AccessControlPolicy argument of put_object_acls for an object
    owned by the main user, not the alt user
    A grant is a dictionary in the form of:
    {u'Grantee': {u'Type': 'type', u'DisplayName': 'name', u'ID': 'id'}, u'Permission': 'PERM'}
    """
    client = get_client()
    main_user_id = get_main_user_id()
    main_display_name = get_main_display_name()

    response = client.get_bucket_acl(Bucket=bucket_name)

    grants = response['Grants']
    grants.append(grant)

    grant = {'Grants': grants, 'Owner': {'DisplayName': main_display_name, 'ID': main_user_id}}

    return grant

def _check_object_acl(permission):
    """
    Sets the permission on an object then checks to see
    if it was set
    """
    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object_acl(Bucket=bucket_name, Key='foo')

    policy = {}
    policy['Owner'] = response['Owner']
    policy['Grants'] = response['Grants']
    policy['Grants'][0]['Permission'] = permission

    client.put_object_acl(Bucket=bucket_name, Key='foo', AccessControlPolicy=policy)

    response = client.get_object_acl(Bucket=bucket_name, Key='foo')
    grants = response['Grants']

    main_user_id = get_main_user_id()
    main_display_name = get_main_display_name()

    check_grants(
        grants,
        [
            dict(
                Permission=permission,
                ID=main_user_id,
                DisplayName=main_display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ],
        )


def _bucket_acl_grant_userid(permission):
    """
    create a new bucket, grant a specific user the specified
    permission, read back the acl and verify correct setting
    """
    bucket_name = get_new_bucket()
    client = get_client()

    main_user_id = get_main_user_id()
    main_display_name = get_main_display_name()

    alt_user_id = get_alt_user_id()
    alt_display_name = get_alt_display_name()

    grant = {'Grantee': {'ID': alt_user_id, 'Type': 'CanonicalUser' }, 'Permission': permission}

    grant = add_bucket_user_grant(bucket_name, grant)

    client.put_bucket_acl(Bucket=bucket_name, AccessControlPolicy=grant)

    response = client.get_bucket_acl(Bucket=bucket_name)

    grants = response['Grants']
    check_grants(
        grants,
        [
            dict(
                Permission=permission,
                ID=alt_user_id,
                DisplayName=alt_display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            dict(
                Permission='FULL_CONTROL',
                ID=main_user_id,
                DisplayName=main_display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ],
        )

    return bucket_name

def _check_bucket_acl_grant_can_read(bucket_name):
    """
    verify ability to read the specified bucket
    """
    alt_client = get_alt_client()
    response = alt_client.head_bucket(Bucket=bucket_name)

def _check_bucket_acl_grant_cant_read(bucket_name):
    """
    verify inability to read the specified bucket
    """
    alt_client = get_alt_client()
    check_access_denied(alt_client.head_bucket, Bucket=bucket_name)

def _check_bucket_acl_grant_can_readacp(bucket_name):
    """
    verify ability to read acls on specified bucket
    """
    alt_client = get_alt_client()
    alt_client.get_bucket_acl(Bucket=bucket_name)

def _check_bucket_acl_grant_cant_readacp(bucket_name):
    """
    verify inability to read acls on specified bucket
    """
    alt_client = get_alt_client()
    check_access_denied(alt_client.get_bucket_acl, Bucket=bucket_name)

def _check_bucket_acl_grant_can_write(bucket_name):
    """
    verify ability to write the specified bucket
    """
    alt_client = get_alt_client()
    alt_client.put_object(Bucket=bucket_name, Key='foo-write', Body='bar')

def _check_bucket_acl_grant_cant_write(bucket_name):

    """
    verify inability to write the specified bucket
    """
    alt_client = get_alt_client()
    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key='foo-write', Body='bar')

def _check_bucket_acl_grant_can_writeacp(bucket_name):
    """
    verify ability to set acls on the specified bucket
    """
    alt_client = get_alt_client()
    alt_client.put_bucket_acl(Bucket=bucket_name, ACL='public-read')

def _check_bucket_acl_grant_cant_writeacp(bucket_name):
    """
    verify inability to set acls on the specified bucket
    """
    alt_client = get_alt_client()
    check_access_denied(alt_client.put_bucket_acl,Bucket=bucket_name, ACL='public-read')

def _get_acl_header(user_id=None, perms=None):
    all_headers = ["read", "write", "read-acp", "write-acp", "full-control"]
    headers = []

    if user_id == None:
        user_id = get_alt_user_id()

    if perms != None:
        for perm in perms:
            header = ("x-amz-grant-{perm}".format(perm=perm), "id={uid}".format(uid=user_id))
            headers.append(header)

    else:
        for perm in all_headers:
            header = ("x-amz-grant-{perm}".format(perm=perm), "id={uid}".format(uid=user_id))
            headers.append(header)

    return headers

def _setup_access(bucket_acl, object_acl):
    """
    Simple test fixture: create a bucket with given ACL, with objects:
    - a: owning user, given ACL
    - a2: same object accessed by some other user
    - b: owning user, default ACL in bucket w/given ACL
    - b2: same object accessed by a some other user
    """
    bucket_name = get_new_bucket()
    client = get_client()

    key1 = 'foo'
    key2 = 'bar'
    newkey = 'new'

    client.put_bucket_acl(Bucket=bucket_name, ACL=bucket_acl)
    client.put_object(Bucket=bucket_name, Key=key1, Body='foocontent')
    client.put_object_acl(Bucket=bucket_name, Key=key1, ACL=object_acl)
    client.put_object(Bucket=bucket_name, Key=key2, Body='barcontent')

    return bucket_name, key1, key2, newkey

def get_bucket_key_names(bucket_name):
    objs_list = get_objects_list(bucket_name)
    return frozenset(obj for obj in objs_list)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all buckets')
@attr(assertion='returns all expected buckets')
def test_buckets_create_then_list():
    client = get_client()
    bucket_names = []
    for i in range(5):
        bucket_name = get_new_bucket_name()
        bucket_names.append(bucket_name)

    for name in bucket_names:
        client.create_bucket(Bucket=name)

    response = client.list_buckets()
    bucket_dicts = response['Buckets']
    buckets_list = []

    buckets_list = get_buckets_list()

    for name in bucket_names:
        if name not in buckets_list:
            raise RuntimeError("S3 implementation's GET on Service did not return bucket we created: %r", bucket.name)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all buckets (bad auth)')
@attr(assertion='fails 403')
def test_list_buckets_invalid_auth():
    bad_auth_client = get_bad_auth_client()
    e = assert_raises(ClientError, bad_auth_client.list_buckets)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'InvalidAccessKeyId')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all buckets (bad auth)')
@attr(assertion='fails 403')
def test_list_buckets_bad_auth():
    main_access_key = get_main_aws_access_key()
    bad_auth_client = get_bad_auth_client(aws_access_key_id=main_access_key)
    e = assert_raises(ClientError, bad_auth_client.list_buckets)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'SignatureDoesNotMatch')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='create bucket')
@attr(assertion='name starts with alphabetic works')
# this test goes outside the user-configure prefix because it needs to
# control the initial character of the bucket name
@nose.with_setup(
    setup=lambda: nuke_prefixed_buckets(prefix='a'+get_prefix()),
    teardown=lambda: nuke_prefixed_buckets(prefix='a'+get_prefix()),
    )
def test_bucket_create_naming_good_starts_alpha():
    check_good_bucket_name('foo', _prefix='a'+get_prefix())

@attr(resource='bucket')
@attr(method='put')
@attr(operation='create bucket')
@attr(assertion='name starts with numeric works')
# this test goes outside the user-configure prefix because it needs to
# control the initial character of the bucket name
@nose.with_setup(
    setup=lambda: nuke_prefixed_buckets(prefix='0'+get_prefix()),
    teardown=lambda: nuke_prefixed_buckets(prefix='0'+get_prefix()),
    )
def test_bucket_create_naming_good_starts_digit():
    check_good_bucket_name('foo', _prefix='0'+get_prefix())

@attr(resource='bucket')
@attr(method='put')
@attr(operation='create bucket')
@attr(assertion='name containing dot works')
def test_bucket_create_naming_good_contains_period():
    check_good_bucket_name('aaa.111')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='create bucket')
@attr(assertion='name containing hyphen works')
def test_bucket_create_naming_good_contains_hyphen():
    check_good_bucket_name('aaa-111')

@attr(resource='object')
@attr(method='put')
@attr(operation='create and list objects with special names')
@attr(assertion='special names work')
def test_bucket_create_special_key_names():
    key_names = [
        ' ',
        '"',
        '$',
        '%',
        '&',
        '\'',
        '<',
        '>',
        '_',
        '_ ',
        '_ _',
        '__',
    ]

    bucket_name = _create_objects(keys=key_names)

    objs_list = get_objects_list(bucket_name)
    eq(key_names, objs_list)

    client = get_client()

    for name in key_names:
        eq((name in objs_list), True)
        response = client.get_object(Bucket=bucket_name, Key=name)
        body = _get_body(response)
        eq(name, body)
        client.put_object_acl(Bucket=bucket_name, Key=name, ACL='private')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='create and list objects with underscore as prefix, list using prefix')
@attr(assertion='listing works correctly')
def test_bucket_list_special_prefix():
    key_names = ['_bla/1', '_bla/2', '_bla/3', '_bla/4', 'abcd']
    bucket_name = _create_objects(keys=key_names)

    objs_list = get_objects_list(bucket_name)

    eq(len(objs_list), 5)

    objs_list = get_objects_list(bucket_name, prefix='_bla/')
    eq(len(objs_list), 4)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy zero sized object in same bucket')
@attr(assertion='works')
def test_object_copy_zero_size():
    key = 'foo123bar'
    bucket_name = _create_objects(keys=[key])
    fp_a = FakeWriteFile(0, '')
    client = get_client()
    client.put_object(Bucket=bucket_name, Key=key, Body=fp_a)

    copy_source = {'Bucket': bucket_name, 'Key': key}

    client.copy(copy_source, bucket_name, 'bar321foo')
    response = client.get_object(Bucket=bucket_name, Key='bar321foo')
    eq(response['ContentLength'], 0)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object in same bucket')
@attr(assertion='works')
def test_object_copy_same_bucket():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}

    client.copy(copy_source, bucket_name, 'bar321foo')

    response = client.get_object(Bucket=bucket_name, Key='bar321foo')
    body = _get_body(response)
    eq('foo', body)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object with content-type')
@attr(assertion='works')
def test_object_copy_verify_contenttype():
    bucket_name = get_new_bucket()
    client = get_client()

    content_type = 'text/bla'
    client.put_object(Bucket=bucket_name, ContentType=content_type, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}

    client.copy(copy_source, bucket_name, 'bar321foo')

    response = client.get_object(Bucket=bucket_name, Key='bar321foo')
    body = _get_body(response)
    eq('foo', body)
    response_content_type = response['ContentType']
    eq(response_content_type, content_type)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object to itself')
@attr(assertion='fails')
def test_object_copy_to_itself():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}

    e = assert_raises(ClientError, client.copy, copy_source, bucket_name, 'foo123bar')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidRequest')

@attr(resource='object')
@attr(method='put')
@attr(operation='modify object metadata by copying')
@attr(assertion='fails')
def test_object_copy_to_itself_with_metadata():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo123bar', Body='foo')
    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}
    metadata = {'foo': 'bar'}

    client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key='foo123bar', Metadata=metadata, MetadataDirective='REPLACE')
    response = client.get_object(Bucket=bucket_name, Key='foo123bar')
    eq(response['Metadata'], metadata)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object from different bucket')
@attr(assertion='works')
def test_object_copy_diff_bucket():
    bucket_name1 = get_new_bucket()
    bucket_name2 = get_new_bucket()

    client = get_client()
    client.put_object(Bucket=bucket_name1, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name1, 'Key': 'foo123bar'}

    client.copy(copy_source, bucket_name2, 'bar321foo')

    response = client.get_object(Bucket=bucket_name2, Key='bar321foo')
    body = _get_body(response)
    eq('foo', body)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy a non-owned object in a non-owned bucket, but with perms')
@attr(assertion='works')
def test_object_copy_not_owned_object_bucket():
    client = get_client()
    alt_client = get_alt_client()
    bucket_name = get_new_bucket_name()
    client.create_bucket(Bucket=bucket_name)
    client.put_object(Bucket=bucket_name, Key='foo123bar', Body='foo')

    alt_user_id = get_alt_user_id()

    grant = {'Grantee': {'ID': alt_user_id, 'Type': 'CanonicalUser' }, 'Permission': 'FULL_CONTROL'}
    grants = add_obj_user_grant(bucket_name, 'foo123bar', grant)
    client.put_object_acl(Bucket=bucket_name, Key='foo123bar', AccessControlPolicy=grants)

    grant = add_bucket_user_grant(bucket_name, grant)
    client.put_bucket_acl(Bucket=bucket_name, AccessControlPolicy=grant)

    alt_client.get_object(Bucket=bucket_name, Key='foo123bar')

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}
    alt_client.copy(copy_source, bucket_name, 'bar321foo')

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object and change acl')
@attr(assertion='works')
def test_object_copy_canned_acl():
    bucket_name = get_new_bucket()
    client = get_client()
    alt_client = get_alt_client()
    client.put_object(Bucket=bucket_name, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}
    client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key='bar321foo', ACL='public-read')
    # check ACL is applied by doing GET from another user
    alt_client.get_object(Bucket=bucket_name, Key='bar321foo')


    metadata={'abc': 'def'}
    copy_source = {'Bucket': bucket_name, 'Key': 'bar321foo'}
    client.copy_object(ACL='public-read', Bucket=bucket_name, CopySource=copy_source, Key='foo123bar', Metadata=metadata, MetadataDirective='REPLACE')

    # check ACL is applied by doing GET from another user
    alt_client.get_object(Bucket=bucket_name, Key='foo123bar')

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object and retain metadata')
def test_object_copy_retaining_metadata():
    for size in [3, 1024 * 1024]:
        bucket_name = get_new_bucket()
        client = get_client()
        content_type = 'audio/ogg'

        metadata = {'key1': 'value1', 'key2': 'value2'}
        client.put_object(Bucket=bucket_name, Key='foo123bar', Metadata=metadata, ContentType=content_type, Body=bytearray(size))

        copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}
        client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key='bar321foo')

        response = client.get_object(Bucket=bucket_name, Key='bar321foo')
        eq(content_type, response['ContentType'])
        eq(metadata, response['Metadata'])
        body = _get_body(response)
        eq(size, response['ContentLength'])

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object and replace metadata')
def test_object_copy_replacing_metadata():
    for size in [3, 1024 * 1024]:
        bucket_name = get_new_bucket()
        client = get_client()
        content_type = 'audio/ogg'

        metadata = {'key1': 'value1', 'key2': 'value2'}
        client.put_object(Bucket=bucket_name, Key='foo123bar', Metadata=metadata, ContentType=content_type, Body=bytearray(size))

        metadata = {'key3': 'value3', 'key2': 'value2'}
        content_type = 'audio/mpeg'

        copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}
        client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key='bar321foo', Metadata=metadata, MetadataDirective='REPLACE', ContentType=content_type)

        response = client.get_object(Bucket=bucket_name, Key='bar321foo')
        eq(content_type, response['ContentType'])
        eq(metadata, response['Metadata'])
        eq(size, response['ContentLength'])

@attr(resource='object')
@attr(method='put')
@attr(operation='copy from non-existent bucket')
def test_object_copy_bucket_not_found():
    bucket_name = get_new_bucket()
    client = get_client()

    copy_source = {'Bucket': bucket_name + "-fake", 'Key': 'foo123bar'}
    e = assert_raises(ClientError, client.copy, copy_source, bucket_name, 'bar321foo')
    status = _get_status(e.response)
    eq(status, 404)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy from non-existent object')
def test_object_copy_key_not_found():
    bucket_name = get_new_bucket()
    client = get_client()

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}
    e = assert_raises(ClientError, client.copy, copy_source, bucket_name, 'bar321foo')
    status = _get_status(e.response)
    eq(status, 404)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object to/from versioned bucket')
@attr(assertion='works')
@attr('versioning')
def test_object_copy_versioned_bucket():
    bucket_name = get_new_bucket()
    client = get_client()
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    size = 1*5
    data = bytearray(size)
    data_str = data.decode()
    key1 = 'foo123bar'
    client.put_object(Bucket=bucket_name, Key=key1, Body=data)

    response = client.get_object(Bucket=bucket_name, Key=key1)
    version_id = response['VersionId']

    # copy object in the same bucket
    copy_source = {'Bucket': bucket_name, 'Key': key1, 'VersionId': version_id}
    key2 = 'bar321foo'
    client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key=key2)
    response = client.get_object(Bucket=bucket_name, Key=key2)
    body = _get_body(response)
    eq(data_str, body)
    eq(size, response['ContentLength'])


    # second copy
    version_id2 = response['VersionId']
    copy_source = {'Bucket': bucket_name, 'Key': key2, 'VersionId': version_id2}
    key3 = 'bar321foo2'
    client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key=key3)
    response = client.get_object(Bucket=bucket_name, Key=key3)
    body = _get_body(response)
    eq(data_str, body)
    eq(size, response['ContentLength'])

    # copy to another versioned bucket
    bucket_name2 = get_new_bucket()
    check_configure_versioning_retry(bucket_name2, "Enabled", "Enabled")
    copy_source = {'Bucket': bucket_name, 'Key': key1, 'VersionId': version_id}
    key4 = 'bar321foo3'
    client.copy_object(Bucket=bucket_name2, CopySource=copy_source, Key=key4)
    response = client.get_object(Bucket=bucket_name2, Key=key4)
    body = _get_body(response)
    eq(data_str, body)
    eq(size, response['ContentLength'])

    # copy to another non versioned bucket
    bucket_name3 = get_new_bucket()
    copy_source = {'Bucket': bucket_name, 'Key': key1, 'VersionId': version_id}
    key5 = 'bar321foo4'
    client.copy_object(Bucket=bucket_name3, CopySource=copy_source, Key=key5)
    response = client.get_object(Bucket=bucket_name3, Key=key5)
    body = _get_body(response)
    eq(data_str, body)
    eq(size, response['ContentLength'])

    # copy from a non versioned bucket
    copy_source = {'Bucket': bucket_name3, 'Key': key5}
    key6 = 'foo123bar2'
    client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key=key6)
    response = client.get_object(Bucket=bucket_name, Key=key6)
    body = _get_body(response)
    eq(data_str, body)
    eq(size, response['ContentLength'])

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object to/from versioned bucket with url-encoded name')
@attr(assertion='works')
@attr('versioning')
def test_object_copy_versioned_url_encoding():
    bucket = get_new_bucket_resource()
    check_configure_versioning_retry(bucket.name, "Enabled", "Enabled")
    src_key = 'foo?bar'
    src = bucket.put_object(Key=src_key)
    src.load() # HEAD request tests that the key exists

    # copy object in the same bucket
    dst_key = 'bar&foo'
    dst = bucket.Object(dst_key)
    dst.copy_from(CopySource={'Bucket': src.bucket_name, 'Key': src.key, 'VersionId': src.version_id})
    dst.load() # HEAD request tests that the key exists

def generate_random(size, part_size=5*1024*1024):
    """
    Generate the specified number random data.
    (actually each MB is a repetition of the first KB)
    """
    chunk = 1024
    allowed = string.ascii_letters
    for x in range(0, size, part_size):
        strpart = ''.join([allowed[random.randint(0, len(allowed) - 1)] for _ in range(chunk)])
        s = ''
        left = size - x
        this_part_size = min(left, part_size)
        for y in range(this_part_size // chunk):
            s = s + strpart
        if this_part_size > len(s):
            s = s + strpart[0:this_part_size - len(s)]
        yield s
        if (x == size):
            return

def _multipart_upload(bucket_name, key, size, part_size=5*1024*1024, client=None, content_type=None, metadata=None, resend_parts=[]):
    """
    generate a multi-part upload for a random file of specifed size,
    if requested, generate a list of the parts
    return the upload descriptor
    """
    if client == None:
        client = get_client()


    if content_type == None and metadata == None:
        response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    else:
        response = client.create_multipart_upload(Bucket=bucket_name, Key=key, Metadata=metadata, ContentType=content_type)

    upload_id = response['UploadId']
    s = ''
    parts = []
    for i, part in enumerate(generate_random(size, part_size)):
        # part_num is necessary because PartNumber for upload_part and in parts must start at 1 and i starts at 0
        part_num = i+1
        s += part
        response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=part_num, Body=part)
        parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': part_num})
        if i in resend_parts:
            client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=part_num, Body=part)

    return (upload_id, s, parts)

@attr(resource='object')
@attr(method='put')
@attr(operation='test copy object of a multipart upload')
@attr(assertion='successful')
@attr('versioning')
def test_object_copy_versioning_multipart_upload():
    bucket_name = get_new_bucket()
    client = get_client()
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key1 = "srcmultipart"
    key1_metadata = {'foo': 'bar'}
    content_type = 'text/bla'
    objlen = 30 * 1024 * 1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key1, size=objlen, content_type=content_type, metadata=key1_metadata)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key1, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=bucket_name, Key=key1)
    key1_size = response['ContentLength']
    version_id = response['VersionId']

    # copy object in the same bucket
    copy_source = {'Bucket': bucket_name, 'Key': key1, 'VersionId': version_id}
    key2 = 'dstmultipart'
    client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key=key2)
    response = client.get_object(Bucket=bucket_name, Key=key2)
    version_id2 = response['VersionId']
    body = _get_body(response)
    eq(data, body)
    eq(key1_size, response['ContentLength'])
    eq(key1_metadata, response['Metadata'])
    eq(content_type, response['ContentType'])

    # second copy
    copy_source = {'Bucket': bucket_name, 'Key': key2, 'VersionId': version_id2}
    key3 = 'dstmultipart2'
    client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key=key3)
    response = client.get_object(Bucket=bucket_name, Key=key3)
    body = _get_body(response)
    eq(data, body)
    eq(key1_size, response['ContentLength'])
    eq(key1_metadata, response['Metadata'])
    eq(content_type, response['ContentType'])

    # copy to another versioned bucket
    bucket_name2 = get_new_bucket()
    check_configure_versioning_retry(bucket_name2, "Enabled", "Enabled")

    copy_source = {'Bucket': bucket_name, 'Key': key1, 'VersionId': version_id}
    key4 = 'dstmultipart3'
    client.copy_object(Bucket=bucket_name2, CopySource=copy_source, Key=key4)
    response = client.get_object(Bucket=bucket_name2, Key=key4)
    body = _get_body(response)
    eq(data, body)
    eq(key1_size, response['ContentLength'])
    eq(key1_metadata, response['Metadata'])
    eq(content_type, response['ContentType'])

    # copy to another non versioned bucket
    bucket_name3 = get_new_bucket()
    copy_source = {'Bucket': bucket_name, 'Key': key1, 'VersionId': version_id}
    key5 = 'dstmultipart4'
    client.copy_object(Bucket=bucket_name3, CopySource=copy_source, Key=key5)
    response = client.get_object(Bucket=bucket_name3, Key=key5)
    body = _get_body(response)
    eq(data, body)
    eq(key1_size, response['ContentLength'])
    eq(key1_metadata, response['Metadata'])
    eq(content_type, response['ContentType'])

    # copy from a non versioned bucket
    copy_source = {'Bucket': bucket_name3, 'Key': key5}
    key6 = 'dstmultipart5'
    client.copy_object(Bucket=bucket_name3, CopySource=copy_source, Key=key6)
    response = client.get_object(Bucket=bucket_name3, Key=key6)
    body = _get_body(response)
    eq(data, body)
    eq(key1_size, response['ContentLength'])
    eq(key1_metadata, response['Metadata'])
    eq(content_type, response['ContentType'])

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart upload without parts')
def test_multipart_upload_empty():
    bucket_name = get_new_bucket()
    client = get_client()

    key1 = "mymultipart"
    objlen = 0
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key1, size=objlen)
    e = assert_raises(ClientError, client.complete_multipart_upload,Bucket=bucket_name, Key=key1, UploadId=upload_id)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidRequest')

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart uploads with single small part')
def test_multipart_upload_small():
    bucket_name = get_new_bucket()
    client = get_client()

    key1 = "mymultipart"
    objlen = 1
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key1, size=objlen)
    response = client.complete_multipart_upload(Bucket=bucket_name, Key=key1, UploadId=upload_id, MultipartUpload={'Parts': parts})
    response = client.get_object(Bucket=bucket_name, Key=key1)
    eq(response['ContentLength'], objlen)

def _create_key_with_random_content(keyname, size=7*1024*1024, bucket_name=None, client=None):
    if bucket_name is None:
        bucket_name = get_new_bucket()

    if client == None:
        client = get_client()

    data_str = str(next(generate_random(size, size)))
    data = bytes(data_str, 'utf-8')
    client.put_object(Bucket=bucket_name, Key=keyname, Body=data)

    return bucket_name

def _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size, client=None, part_size=5*1024*1024, version_id=None):

    if(client == None):
        client = get_client()

    response = client.create_multipart_upload(Bucket=dest_bucket_name, Key=dest_key)
    upload_id = response['UploadId']

    if(version_id == None):
        copy_source = {'Bucket': src_bucket_name, 'Key': src_key}
    else:
        copy_source = {'Bucket': src_bucket_name, 'Key': src_key, 'VersionId': version_id}

    parts = []

    i = 0
    for start_offset in range(0, size, part_size):
        end_offset = min(start_offset + part_size - 1, size - 1)
        part_num = i+1
        copy_source_range = 'bytes={start}-{end}'.format(start=start_offset, end=end_offset)
        response = client.upload_part_copy(Bucket=dest_bucket_name, Key=dest_key, CopySource=copy_source, PartNumber=part_num, UploadId=upload_id, CopySourceRange=copy_source_range)
        parts.append({'ETag': response['CopyPartResult']['ETag'], 'PartNumber': part_num})
        i = i+1

    return (upload_id, parts)

def _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name, version_id=None):
    client = get_client()

    if(version_id == None):
        response = client.get_object(Bucket=src_bucket_name, Key=src_key)
    else:
        response = client.get_object(Bucket=src_bucket_name, Key=src_key, VersionId=version_id)
    src_size = response['ContentLength']

    response = client.get_object(Bucket=dest_bucket_name, Key=dest_key)
    dest_size = response['ContentLength']
    dest_data = _get_body(response)
    assert(src_size >= dest_size)

    r = 'bytes={s}-{e}'.format(s=0, e=dest_size-1)
    if(version_id == None):
        response = client.get_object(Bucket=src_bucket_name, Key=src_key, Range=r)
    else:
        response = client.get_object(Bucket=src_bucket_name, Key=src_key, Range=r, VersionId=version_id)
    src_data = _get_body(response)
    eq(src_data, dest_data)

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copies with single small part')
def test_multipart_copy_small():
    src_key = 'foo'
    src_bucket_name = _create_key_with_random_content(src_key)

    dest_bucket_name = get_new_bucket()
    dest_key = "mymultipart"
    size = 1
    client = get_client()

    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=dest_bucket_name, Key=dest_key)
    eq(size, response['ContentLength'])
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copies with an invalid range')
def test_multipart_copy_invalid_range():
    client = get_client()
    src_key = 'source'
    src_bucket_name = _create_key_with_random_content(src_key, size=5)

    response = client.create_multipart_upload(Bucket=src_bucket_name, Key='dest')
    upload_id = response['UploadId']

    copy_source = {'Bucket': src_bucket_name, 'Key': src_key}
    copy_source_range = 'bytes={start}-{end}'.format(start=0, end=21)

    e = assert_raises(ClientError, client.upload_part_copy,Bucket=src_bucket_name, Key='dest', UploadId=upload_id, CopySource=copy_source, CopySourceRange=copy_source_range, PartNumber=1)
    status, error_code = _get_status_and_error_code(e.response)
    valid_status = [400, 416]
    if not status in valid_status:
       raise AssertionError("Invalid response " + str(status))
    eq(error_code, 'InvalidArgument')


@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copy with an improperly formatted range')
# TODO: remove fails_on_rgw when https://tracker.ceph.com/issues/40795 is resolved
@attr('fails_on_rgw')
def test_multipart_copy_improper_range():
    client = get_client()
    src_key = 'source'
    src_bucket_name = _create_key_with_random_content(src_key, size=5)

    response = client.create_multipart_upload(
        Bucket=src_bucket_name, Key='dest')
    upload_id = response['UploadId']

    copy_source = {'Bucket': src_bucket_name, 'Key': src_key}
    test_ranges = ['{start}-{end}'.format(start=0, end=2),
                   'bytes={start}'.format(start=0),
                   'bytes=hello-world',
                   'bytes=0-bar',
                   'bytes=hello-',
                   'bytes=0-2,3-5']

    for test_range in test_ranges:
        e = assert_raises(ClientError, client.upload_part_copy,
                          Bucket=src_bucket_name, Key='dest',
                          UploadId=upload_id,
                          CopySource=copy_source,
                          CopySourceRange=test_range,
                          PartNumber=1)
        status, error_code = _get_status_and_error_code(e.response)
        eq(status, 400)
        eq(error_code, 'InvalidArgument')


@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copies without x-amz-copy-source-range')
def test_multipart_copy_without_range():
    client = get_client()
    src_key = 'source'
    src_bucket_name = _create_key_with_random_content(src_key, size=10)
    dest_bucket_name = get_new_bucket_name()
    get_new_bucket(name=dest_bucket_name)
    dest_key = "mymultipartcopy"

    response = client.create_multipart_upload(Bucket=dest_bucket_name, Key=dest_key)
    upload_id = response['UploadId']
    parts = []

    copy_source = {'Bucket': src_bucket_name, 'Key': src_key}
    part_num = 1
    copy_source_range = 'bytes={start}-{end}'.format(start=0, end=9)

    response = client.upload_part_copy(Bucket=dest_bucket_name, Key=dest_key, CopySource=copy_source, PartNumber=part_num, UploadId=upload_id)

    parts.append({'ETag': response['CopyPartResult']['ETag'], 'PartNumber': part_num})
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=dest_bucket_name, Key=dest_key)
    eq(response['ContentLength'], 10)
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copies with single small part')
def test_multipart_copy_special_names():
    src_bucket_name = get_new_bucket()

    dest_bucket_name = get_new_bucket()

    dest_key = "mymultipart"
    size = 1
    client = get_client()

    for src_key in (' ', '_', '__', '?versionId'):
        _create_key_with_random_content(src_key, bucket_name=src_bucket_name)
        (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
        response = client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
        response = client.get_object(Bucket=dest_bucket_name, Key=dest_key)
        eq(size, response['ContentLength'])
        _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

def _check_content_using_range(key, bucket_name, data, step):
    client = get_client()
    response = client.get_object(Bucket=bucket_name, Key=key)
    size = response['ContentLength']

    for ofs in range(0, size, step):
        toread = size - ofs
        if toread > step:
            toread = step
        end = ofs + toread - 1
        r = 'bytes={s}-{e}'.format(s=ofs, e=end)
        response = client.get_object(Bucket=bucket_name, Key=key, Range=r)
        eq(response['ContentLength'], toread)
        body = _get_body(response)
        eq(body, data[ofs:end+1])

@attr(resource='object')
@attr(method='put')
@attr(operation='complete multi-part upload')
@attr(assertion='successful')
@attr('fails_on_aws')
def test_multipart_upload():
    bucket_name = get_new_bucket()
    key="mymultipart"
    content_type='text/bla'
    objlen = 30 * 1024 * 1024
    metadata = {'foo': 'bar'}
    client = get_client()

    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen, content_type=content_type, metadata=metadata)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.head_bucket(Bucket=bucket_name)
    rgw_bytes_used = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-bytes-used', objlen))
    eq(rgw_bytes_used, objlen)

    rgw_object_count = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-object-count', 1))
    eq(rgw_object_count, 1)

    response = client.get_object(Bucket=bucket_name, Key=key)
    eq(response['ContentType'], content_type)
    eq(response['Metadata'], metadata)
    body = _get_body(response)
    eq(len(body), response['ContentLength'])
    eq(body, data)

    _check_content_using_range(key, bucket_name, data, 1000000)
    _check_content_using_range(key, bucket_name, data, 10000000)

def check_versioning(bucket_name, status):
    client = get_client()

    try:
        response = client.get_bucket_versioning(Bucket=bucket_name)
        eq(response['Status'], status)
    except KeyError:
        eq(status, None)

# amazon is eventual consistent, retry a bit if failed
def check_configure_versioning_retry(bucket_name, status, expected_string):
    client = get_client()
    client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'Status': status})

    read_status = None

    for i in range(5):
        try:
            response = client.get_bucket_versioning(Bucket=bucket_name)
            read_status = response['Status']
        except KeyError:
            read_status = None

        if (expected_string == read_status):
            break

        time.sleep(1)

    eq(expected_string, read_status)

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copies of versioned objects')
@attr('versioning')
def test_multipart_copy_versioned():
    src_bucket_name = get_new_bucket()
    dest_bucket_name = get_new_bucket()

    dest_key = "mymultipart"
    check_versioning(src_bucket_name, None)

    src_key = 'foo'
    check_configure_versioning_retry(src_bucket_name, "Enabled", "Enabled")

    size = 1 * 1024 * 1024
    _create_key_with_random_content(src_key, size=size, bucket_name=src_bucket_name)
    _create_key_with_random_content(src_key, size=size, bucket_name=src_bucket_name)
    _create_key_with_random_content(src_key, size=size, bucket_name=src_bucket_name)

    version_id = []
    client = get_client()
    response = client.list_object_versions(Bucket=src_bucket_name)
    for ver in response['Versions']:
        version_id.append(ver['VersionId'])

    for vid in version_id:
        (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size, version_id=vid)
        response = client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
        response = client.get_object(Bucket=dest_bucket_name, Key=dest_key)
        eq(size, response['ContentLength'])
        _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name, version_id=vid)

def _check_upload_multipart_resend(bucket_name, key, objlen, resend_parts):
    content_type = 'text/bla'
    metadata = {'foo': 'bar'}
    client = get_client()
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen, content_type=content_type, metadata=metadata, resend_parts=resend_parts)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=bucket_name, Key=key)
    eq(response['ContentType'], content_type)
    eq(response['Metadata'], metadata)
    body = _get_body(response)
    eq(len(body), response['ContentLength'])
    eq(body, data)

    _check_content_using_range(key, bucket_name, data, 1000000)
    _check_content_using_range(key, bucket_name, data, 10000000)

@attr(resource='object')
@attr(method='put')
@attr(operation='complete multiple multi-part upload with different sizes')
@attr(resource='object')
@attr(method='put')
@attr(operation='complete multi-part upload')
@attr(assertion='successful')
def test_multipart_upload_resend_part():
    bucket_name = get_new_bucket()
    key="mymultipart"
    objlen = 30 * 1024 * 1024

    _check_upload_multipart_resend(bucket_name, key, objlen, [0])
    _check_upload_multipart_resend(bucket_name, key, objlen, [1])
    _check_upload_multipart_resend(bucket_name, key, objlen, [2])
    _check_upload_multipart_resend(bucket_name, key, objlen, [1,2])
    _check_upload_multipart_resend(bucket_name, key, objlen, [0,1,2,3,4,5])

@attr(assertion='successful')
def test_multipart_upload_multiple_sizes():
    bucket_name = get_new_bucket()
    key="mymultipart"
    client = get_client()

    objlen = 5*1024*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    objlen = 5*1024*1024+100*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    objlen = 5*1024*1024+600*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    objlen = 10*1024*1024+100*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    objlen = 10*1024*1024+600*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    objlen = 10*1024*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

@attr(assertion='successful')
def test_multipart_copy_multiple_sizes():
    src_key = 'foo'
    src_bucket_name = _create_key_with_random_content(src_key, 12*1024*1024)

    dest_bucket_name = get_new_bucket()
    dest_key="mymultipart"
    client = get_client()

    size = 5*1024*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

    size = 5*1024*1024+100*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

    size = 5*1024*1024+600*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

    size = 10*1024*1024+100*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

    size = 10*1024*1024+600*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

    size = 10*1024*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

@attr(resource='object')
@attr(method='put')
@attr(operation='check failure on multiple multi-part upload with size too small')
@attr(assertion='fails 400')
def test_multipart_upload_size_too_small():
    bucket_name = get_new_bucket()
    key="mymultipart"
    client = get_client()

    size = 100*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=size, part_size=10*1024)
    e = assert_raises(ClientError, client.complete_multipart_upload, Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'EntityTooSmall')

def gen_rand_string(size, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def _do_test_multipart_upload_contents(bucket_name, key, num_parts):
    payload=gen_rand_string(5)*1024*1024
    client = get_client()

    response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    upload_id = response['UploadId']

    parts = []

    for part_num in range(0, num_parts):
        part = bytes(payload, 'utf-8')
        response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=part_num+1, Body=part)
        parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': part_num+1})

    last_payload = '123'*1024*1024
    last_part = bytes(last_payload, 'utf-8')
    response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=num_parts+1, Body=last_part)
    parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': num_parts+1})

    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=bucket_name, Key=key)
    test_string = _get_body(response)

    all_payload = payload*num_parts + last_payload

    assert test_string == all_payload

    return all_payload

@attr(resource='object')
@attr(method='put')
@attr(operation='check contents of multi-part upload')
@attr(assertion='successful')
def test_multipart_upload_contents():
    bucket_name = get_new_bucket()
    _do_test_multipart_upload_contents(bucket_name, 'mymultipart', 3)

@attr(resource='object')
@attr(method='put')
@attr(operation=' multi-part upload overwrites existing key')
@attr(assertion='successful')
def test_multipart_upload_overwrite_existing_object():
    bucket_name = get_new_bucket()
    client = get_client()
    key = 'mymultipart'
    payload='12345'*1024*1024
    num_parts=2
    client.put_object(Bucket=bucket_name, Key=key, Body=payload)


    response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    upload_id = response['UploadId']

    parts = []

    for part_num in range(0, num_parts):
        response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=part_num+1, Body=payload)
        parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': part_num+1})

    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=bucket_name, Key=key)
    test_string = _get_body(response)

    assert test_string == payload*num_parts

@attr(resource='object')
@attr(method='put')
@attr(operation='abort multi-part upload')
@attr(assertion='successful')
def test_abort_multipart_upload():
    bucket_name = get_new_bucket()
    key="mymultipart"
    objlen = 10 * 1024 * 1024
    client = get_client()

    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.abort_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id)

    response = client.head_bucket(Bucket=bucket_name)
    rgw_bytes_used = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-bytes-used', 0))
    eq(rgw_bytes_used, 0)

    rgw_object_count = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-object-count', 0))
    eq(rgw_object_count, 0)

@attr(resource='object')
@attr(method='put')
@attr(operation='abort non-existent multi-part upload')
@attr(assertion='fails 404')
def test_abort_multipart_upload_not_found():
    bucket_name = get_new_bucket()
    client = get_client()
    key="mymultipart"
    client.put_object(Bucket=bucket_name, Key=key)

    e = assert_raises(ClientError, client.abort_multipart_upload, Bucket=bucket_name, Key=key, UploadId='56788')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchUpload')

@attr(resource='object')
@attr(method='put')
@attr(operation='multi-part upload with missing part')
def test_multipart_upload_missing_part():
    bucket_name = get_new_bucket()
    client = get_client()
    key="mymultipart"
    size = 1

    response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    upload_id = response['UploadId']

    parts = []
    response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=1, Body=bytes('\x00', 'utf-8'))
    # 'PartNumber should be 1'
    parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': 9999})

    e = assert_raises(ClientError, client.complete_multipart_upload, Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidPart')

@attr(resource='object')
@attr(method='put')
@attr(operation='multi-part upload with incorrect ETag')
def test_multipart_upload_incorrect_etag():
    bucket_name = get_new_bucket()
    client = get_client()
    key="mymultipart"
    size = 1

    response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    upload_id = response['UploadId']

    parts = []
    response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=1, Body=bytes('\x00', 'utf-8'))
    # 'ETag' should be "93b885adfe0da089cdf634904fd59f71"
    parts.append({'ETag': "ffffffffffffffffffffffffffffffff", 'PartNumber': 1})

    e = assert_raises(ClientError, client.complete_multipart_upload, Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidPart')

def _simple_http_req_100_cont(host, port, is_secure, method, resource):
    """
    Send the specified request w/expect 100-continue
    and await confirmation.
    """
    req_str = '{method} {resource} HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: identity\r\nContent-Length: 123\r\nExpect: 100-continue\r\n\r\n'.format(
            method=method,
            resource=resource,
            host=host,
            )

    req = bytes(req_str, 'utf-8')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if is_secure:
        s = ssl.wrap_socket(s);
    s.settimeout(5)
    s.connect((host, port))
    s.send(req)

    try:
        data = s.recv(1024)
    except socket.error as msg:
        print('got response: ', msg)
        print('most likely server doesn\'t support 100-continue')

    s.close()
    data_str = data.decode()
    l = data_str.split(' ')

    assert l[0].startswith('HTTP')

    return l[1]

def _cors_request_and_check(func, url, headers, expect_status, expect_allow_origin, expect_allow_methods):
    r = func(url, headers=headers)
    eq(r.status_code, expect_status)

    assert r.headers.get('access-control-allow-origin', None) == expect_allow_origin
    assert r.headers.get('access-control-allow-methods', None) == expect_allow_methods

@attr(resource='bucket')
@attr(method='put')
@attr(operation='put tags')
@attr(assertion='succeeds')
@attr('tagging')
def test_set_tagging():
    bucket_name = get_new_bucket()
    client = get_client()

    tags={
        'TagSet': [
            {
                'Key': 'Hello',
                'Value': 'World'
            },
        ]
    }

    e = assert_raises(ClientError, client.get_bucket_tagging, Bucket=bucket_name)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchTagSet')

    client.put_bucket_tagging(Bucket=bucket_name, Tagging=tags)

    response = client.get_bucket_tagging(Bucket=bucket_name)
    eq(len(response['TagSet']), 1)
    eq(response['TagSet'][0]['Key'], 'Hello')
    eq(response['TagSet'][0]['Value'], 'World')

    client.delete_bucket_tagging(Bucket=bucket_name)
    e = assert_raises(ClientError, client.get_bucket_tagging, Bucket=bucket_name)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchTagSet')


class FakeFile(object):
    """
    file that simulates seek, tell, and current character
    """
    def __init__(self, char='A', interrupt=None):
        self.offset = 0
        self.char = bytes(char, 'utf-8')
        self.interrupt = interrupt

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            self.offset = offset
        elif whence == os.SEEK_END:
            self.offset = self.size + offset;
        elif whence == os.SEEK_CUR:
            self.offset += offset

    def tell(self):
        return self.offset

class FakeWriteFile(FakeFile):
    """
    file that simulates interruptable reads of constant data
    """
    def __init__(self, size, char='A', interrupt=None):
        FakeFile.__init__(self, char, interrupt)
        self.size = size

    def read(self, size=-1):
        if size < 0:
            size = self.size - self.offset
        count = min(size, self.size - self.offset)
        self.offset += count

        # Sneaky! do stuff before we return (the last time)
        if self.interrupt != None and self.offset == self.size and count > 0:
            self.interrupt()

        return self.char*count

class FakeReadFile(FakeFile):
    """
    file that simulates writes, interrupting after the second
    """
    def __init__(self, size, char='A', interrupt=None):
        FakeFile.__init__(self, char, interrupt)
        self.interrupted = False
        self.size = 0
        self.expected_size = size

    def write(self, chars):
        eq(chars, self.char*len(chars))
        self.offset += len(chars)
        self.size += len(chars)

        # Sneaky! do stuff on the second seek
        if not self.interrupted and self.interrupt != None \
                and self.offset > 0:
            self.interrupt()
            self.interrupted = True

    def close(self):
        eq(self.size, self.expected_size)

class FakeFileVerifier(object):
    """
    file that verifies expected data has been written
    """
    def __init__(self, char=None):
        self.char = char
        self.size = 0

    def write(self, data):
        size = len(data)
        if self.char == None:
            self.char = data[0]
        self.size += size
        eq(data.decode(), self.char*size)

def _verify_atomic_key_data(bucket_name, key, size=-1, char=None):
    """
    Make sure file is of the expected size and (simulated) content
    """
    fp_verify = FakeFileVerifier(char)
    client = get_client()
    client.download_fileobj(bucket_name, key, fp_verify)
    if size >= 0:
        eq(fp_verify.size, size)

def _test_atomic_read(file_size):
    """
    Create a file of A's, use it to set_contents_from_file.
    Create a file of B's, use it to re-set_contents_from_file.
    Re-read the contents, and confirm we get B's
    """
    bucket_name = get_new_bucket()
    client = get_client()


    fp_a = FakeWriteFile(file_size, 'A')
    client.put_object(Bucket=bucket_name, Key='testobj', Body=fp_a)

    fp_b = FakeWriteFile(file_size, 'B')
    fp_a2 = FakeReadFile(file_size, 'A',
        lambda: client.put_object(Bucket=bucket_name, Key='testobj', Body=fp_b)
        )

    read_client = get_client()

    read_client.download_fileobj(bucket_name, 'testobj', fp_a2)
    fp_a2.close()

    _verify_atomic_key_data(bucket_name, 'testobj', file_size, 'B')

@attr(resource='object')
@attr(method='put')
@attr(operation='read atomicity')
@attr(assertion='1MB successful')
def test_atomic_read_1mb():
    _test_atomic_read(1024*1024)

@attr(resource='object')
@attr(method='put')
@attr(operation='read atomicity')
@attr(assertion='4MB successful')
def test_atomic_read_4mb():
    _test_atomic_read(1024*1024*4)

@attr(resource='object')
@attr(method='put')
@attr(operation='read atomicity')
@attr(assertion='8MB successful')
def test_atomic_read_8mb():
    _test_atomic_read(1024*1024*8)

def _test_atomic_write(file_size):
    """
    Create a file of A's, use it to set_contents_from_file.
    Verify the contents are all A's.
    Create a file of B's, use it to re-set_contents_from_file.
    Before re-set continues, verify content's still A's
    Re-read the contents, and confirm we get B's
    """
    bucket_name = get_new_bucket()
    client = get_client()
    objname = 'testobj'


    # create <file_size> file of A's
    fp_a = FakeWriteFile(file_size, 'A')
    client.put_object(Bucket=bucket_name, Key=objname, Body=fp_a)


    # verify A's
    _verify_atomic_key_data(bucket_name, objname, file_size, 'A')

    # create <file_size> file of B's
    # but try to verify the file before we finish writing all the B's
    fp_b = FakeWriteFile(file_size, 'B',
        lambda: _verify_atomic_key_data(bucket_name, objname, file_size, 'A')
        )

    client.put_object(Bucket=bucket_name, Key=objname, Body=fp_b)

    # verify B's
    _verify_atomic_key_data(bucket_name, objname, file_size, 'B')

@attr(resource='object')
@attr(method='put')
@attr(operation='write atomicity')
@attr(assertion='1MB successful')
def test_atomic_write_1mb():
    _test_atomic_write(1024*1024)

@attr(resource='object')
@attr(method='put')
@attr(operation='write atomicity')
@attr(assertion='4MB successful')
def test_atomic_write_4mb():
    _test_atomic_write(1024*1024*4)

@attr(resource='object')
@attr(method='put')
@attr(operation='write atomicity')
@attr(assertion='8MB successful')
def test_atomic_write_8mb():
    _test_atomic_write(1024*1024*8)

def _test_atomic_dual_write(file_size):
    """
    create an object, two sessions writing different contents
    confirm that it is all one or the other
    """
    bucket_name = get_new_bucket()
    objname = 'testobj'
    client = get_client()
    client.put_object(Bucket=bucket_name, Key=objname)

    # write <file_size> file of B's
    # but before we're done, try to write all A's
    fp_a = FakeWriteFile(file_size, 'A')

    def rewind_put_fp_a():
        fp_a.seek(0)
        client.put_object(Bucket=bucket_name, Key=objname, Body=fp_a)

    fp_b = FakeWriteFile(file_size, 'B', rewind_put_fp_a)
    client.put_object(Bucket=bucket_name, Key=objname, Body=fp_b)

    # verify the file
    _verify_atomic_key_data(bucket_name, objname, file_size, 'B')

@attr(resource='object')
@attr(method='put')
@attr(operation='write one or the other')
@attr(assertion='1MB successful')
def test_atomic_dual_write_1mb():
    _test_atomic_dual_write(1024*1024)

@attr(resource='object')
@attr(method='put')
@attr(operation='write one or the other')
@attr(assertion='4MB successful')
def test_atomic_dual_write_4mb():
    _test_atomic_dual_write(1024*1024*4)

@attr(resource='object')
@attr(method='put')
@attr(operation='write one or the other')
@attr(assertion='8MB successful')
def test_atomic_dual_write_8mb():
    _test_atomic_dual_write(1024*1024*8)

def _test_atomic_conditional_write(file_size):
    """
    Create a file of A's, use it to set_contents_from_file.
    Verify the contents are all A's.
    Create a file of B's, use it to re-set_contents_from_file.
    Before re-set continues, verify content's still A's
    Re-read the contents, and confirm we get B's
    """
    bucket_name = get_new_bucket()
    objname = 'testobj'
    client = get_client()

    # create <file_size> file of A's
    fp_a = FakeWriteFile(file_size, 'A')
    client.put_object(Bucket=bucket_name, Key=objname, Body=fp_a)

    fp_b = FakeWriteFile(file_size, 'B',
        lambda: _verify_atomic_key_data(bucket_name, objname, file_size, 'A')
        )

    # create <file_size> file of B's
    # but try to verify the file before we finish writing all the B's
    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': '*'}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key=objname, Body=fp_b)

    # verify B's
    _verify_atomic_key_data(bucket_name, objname, file_size, 'B')

def _test_atomic_dual_conditional_write(file_size):
    """
    create an object, two sessions writing different contents
    confirm that it is all one or the other
    """
    bucket_name = get_new_bucket()
    objname = 'testobj'
    client = get_client()

    fp_a = FakeWriteFile(file_size, 'A')
    response = client.put_object(Bucket=bucket_name, Key=objname, Body=fp_a)
    _verify_atomic_key_data(bucket_name, objname, file_size, 'A')
    etag_fp_a = response['ETag'].replace('"', '')

    # write <file_size> file of C's
    # but before we're done, try to write all B's
    fp_b = FakeWriteFile(file_size, 'B')
    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': etag_fp_a}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    def rewind_put_fp_b():
        fp_b.seek(0)
        client.put_object(Bucket=bucket_name, Key=objname, Body=fp_b)

    fp_c = FakeWriteFile(file_size, 'C', rewind_put_fp_b)

    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=objname, Body=fp_c)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

    # verify the file
    _verify_atomic_key_data(bucket_name, objname, file_size, 'B')

@attr(resource='object')
@attr(method='put')
@attr(operation='write one or the other')
@attr(assertion='1MB successful')
@attr('fails_on_aws')
# TODO: test not passing with SSL, fix this
@attr('fails_on_rgw')
def test_atomic_dual_conditional_write_1mb():
    _test_atomic_dual_conditional_write(1024*1024)

@attr(resource='object')
@attr(method='put')
@attr(operation='write file in deleted bucket')
@attr(assertion='fail 404')
@attr('fails_on_aws')
# TODO: test not passing with SSL, fix this
@attr('fails_on_rgw')
def test_atomic_write_bucket_gone():
    bucket_name = get_new_bucket()
    client = get_client()

    def remove_bucket():
        client.delete_bucket(Bucket=bucket_name)

    objname = 'foo'
    fp_a = FakeWriteFile(1024*1024, 'A', remove_bucket)

    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=objname, Body=fp_a)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='object')
@attr(method='put')
@attr(operation='begin to overwrite file with multipart upload then abort')
@attr(assertion='read back original key contents')
def test_atomic_multipart_upload_write():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.create_multipart_upload(Bucket=bucket_name, Key='foo')
    upload_id = response['UploadId']

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    client.abort_multipart_upload(Bucket=bucket_name, Key='foo', UploadId=upload_id)

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

class Counter:
    def __init__(self, default_val):
        self.val = default_val

    def inc(self):
        self.val = self.val + 1

class ActionOnCount:
    def __init__(self, trigger_count, action):
        self.count = 0
        self.trigger_count = trigger_count
        self.action = action
        self.result = 0

    def trigger(self):
        self.count = self.count + 1

        if self.count == self.trigger_count:
            self.result = self.action()

@attr(resource='object')
@attr(method='put')
@attr(operation='multipart check for two writes of the same part, first write finishes last')
@attr(assertion='object contains correct content')
@nottest
def test_multipart_resend_first_finishes_last():
    bucket_name = get_new_bucket()
    client = get_client()
    key_name = "mymultipart"

    response = client.create_multipart_upload(Bucket=bucket_name, Key=key_name)
    upload_id = response['UploadId']

    #file_size = 8*1024*1024
    file_size = 8

    counter = Counter(0)
    # upload_part might read multiple times from the object
    # first time when it calculates md5, second time when it writes data
    # out. We want to interject only on the last time, but we can't be
    # sure how many times it's going to read, so let's have a test run
    # and count the number of reads

    fp_dry_run = FakeWriteFile(file_size, 'C',
        lambda: counter.inc()
        )

    parts = []

    response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key_name, PartNumber=1, Body=fp_dry_run)

    parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': 1})
    client.complete_multipart_upload(Bucket=bucket_name, Key=key_name, UploadId=upload_id, MultipartUpload={'Parts': parts})

    client.delete_object(Bucket=bucket_name, Key=key_name)

    # clear parts
    parts[:] = []

    # ok, now for the actual test
    fp_b = FakeWriteFile(file_size, 'B')
    def upload_fp_b():
        response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key_name, Body=fp_b, PartNumber=1)
        parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': 1})

    action = ActionOnCount(counter.val, lambda: upload_fp_b())

    response = client.create_multipart_upload(Bucket=bucket_name, Key=key_name)
    upload_id = response['UploadId']

    fp_a = FakeWriteFile(file_size, 'A',
        lambda: action.trigger()
        )

    response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key_name, PartNumber=1, Body=fp_a)

    parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': 1})
    client.complete_multipart_upload(Bucket=bucket_name, Key=key_name, UploadId=upload_id, MultipartUpload={'Parts': parts})

    _verify_atomic_key_data(bucket_name, key_name, file_size, 'A')

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns correct data, 206')
def test_ranged_request_response_code():
    content = 'testcontent'

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)
    response = client.get_object(Bucket=bucket_name, Key='testobj', Range='bytes=4-7')

    fetched_content = _get_body(response)
    eq(fetched_content, content[4:8])
    eq(response['ResponseMetadata']['HTTPHeaders']['content-range'], 'bytes 4-7/11')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 206)

def _generate_random_string(size):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size))

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns correct data, 206')
def test_ranged_big_request_response_code():
    content = _generate_random_string(8*1024*1024)

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)
    response = client.get_object(Bucket=bucket_name, Key='testobj', Range='bytes=3145728-5242880')

    fetched_content = _get_body(response)
    eq(fetched_content, content[3145728:5242881])
    eq(response['ResponseMetadata']['HTTPHeaders']['content-range'], 'bytes 3145728-5242880/8388608')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 206)

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns correct data, 206')
def test_ranged_request_skip_leading_bytes_response_code():
    content = 'testcontent'

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)
    response = client.get_object(Bucket=bucket_name, Key='testobj', Range='bytes=4-')

    fetched_content = _get_body(response)
    eq(fetched_content, content[4:])
    eq(response['ResponseMetadata']['HTTPHeaders']['content-range'], 'bytes 4-10/11')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 206)

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns correct data, 206')
def test_ranged_request_return_trailing_bytes_response_code():
    content = 'testcontent'

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)
    response = client.get_object(Bucket=bucket_name, Key='testobj', Range='bytes=-7')

    fetched_content = _get_body(response)
    eq(fetched_content, content[-7:])
    eq(response['ResponseMetadata']['HTTPHeaders']['content-range'], 'bytes 4-10/11')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 206)

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns invalid range, 416')
def test_ranged_request_invalid_range():
    content = 'testcontent'

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)

    # test invalid range
    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='testobj', Range='bytes=40-50')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 416)
    eq(error_code, 'InvalidRange')

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns invalid range, 416')
def test_ranged_request_empty_object():
    content = ''

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)

    # test invalid range
    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='testobj', Range='bytes=40-50')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 416)
    eq(error_code, 'InvalidRange')

@attr(resource='bucket')
@attr(method='create')
@attr(operation='create versioned bucket')
@attr(assertion='can create and suspend bucket versioning')
@attr('versioning')
def test_versioning_bucket_create_suspend():
    bucket_name = get_new_bucket()
    check_versioning(bucket_name, None)

    check_configure_versioning_retry(bucket_name, "Suspended", "Suspended")
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    check_configure_versioning_retry(bucket_name, "Suspended", "Suspended")

def check_obj_content(client, bucket_name, key, version_id, content):
    response = client.get_object(Bucket=bucket_name, Key=key, VersionId=version_id)
    if content is not None:
        body = _get_body(response)
        eq(body, content)
    else:
        eq(response['DeleteMarker'], True)

def check_obj_versions(client, bucket_name, key, version_ids, contents):
    # check to see if objects is pointing at correct version

    response = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    # obj versions in versions come out created last to first not first to last like version_ids & contents
    versions.reverse()
    i = 0

    for version in versions:
        eq(version['VersionId'], version_ids[i])
        eq(version['Key'], key)
        check_obj_content(client, bucket_name, key, version['VersionId'], contents[i])
        i += 1

def create_multiple_versions(client, bucket_name, key, num_versions, version_ids = None, contents = None, check_versions = True):
    contents = contents or []
    version_ids = version_ids or []

    for i in range(num_versions):
        body = 'content-{i}'.format(i=i)
        response = client.put_object(Bucket=bucket_name, Key=key, Body=body)
        version_id = response['VersionId']

        contents.append(body)
        version_ids.append(version_id)

    if check_versions:
        check_obj_versions(client, bucket_name, key, version_ids, contents)

    return (version_ids, contents)

def remove_obj_version(client, bucket_name, key, version_ids, contents, index):
    eq(len(version_ids), len(contents))
    index = index % len(version_ids)
    rm_version_id = version_ids.pop(index)
    rm_content = contents.pop(index)

    check_obj_content(client, bucket_name, key, rm_version_id, rm_content)

    client.delete_object(Bucket=bucket_name, Key=key, VersionId=rm_version_id)

    if len(version_ids) != 0:
        check_obj_versions(client, bucket_name, key, version_ids, contents)

def clean_up_bucket(client, bucket_name, key, version_ids):
    for version_id in version_ids:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=version_id)

    client.delete_bucket(Bucket=bucket_name)

def _do_test_create_remove_versions(client, bucket_name, key, num_versions, remove_start_idx, idx_inc):
    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    idx = remove_start_idx

    for j in range(num_versions):
        remove_obj_version(client, bucket_name, key, version_ids, contents, idx)
        idx += idx_inc

    response = client.list_object_versions(Bucket=bucket_name)
    if 'Versions' in response:
        print(response['Versions'])


@attr(resource='object')
@attr(method='create')
@attr(operation='create and remove versioned object')
@attr(assertion='can create access and remove appropriate versions')
@attr('versioning')
def test_versioning_obj_create_read_remove():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'MFADelete': 'Disabled', 'Status': 'Enabled'})
    key = 'testobj'
    num_versions = 5

    _do_test_create_remove_versions(client, bucket_name, key, num_versions, -1, 0)
    _do_test_create_remove_versions(client, bucket_name, key, num_versions, -1, 0)
    _do_test_create_remove_versions(client, bucket_name, key, num_versions, 0, 0)
    _do_test_create_remove_versions(client, bucket_name, key, num_versions, 1, 0)
    _do_test_create_remove_versions(client, bucket_name, key, num_versions, 4, -1)
    _do_test_create_remove_versions(client, bucket_name, key, num_versions, 3, 3)

@attr(resource='object')
@attr(method='create')
@attr(operation='create and remove versioned object and head')
@attr(assertion='can create access and remove appropriate versions')
@attr('versioning')
def test_versioning_obj_create_read_remove_head():
    bucket_name = get_new_bucket()

    client = get_client()
    client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'MFADelete': 'Disabled', 'Status': 'Enabled'})
    key = 'testobj'
    num_versions = 5

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    # removes old head object, checks new one
    removed_version_id = version_ids.pop()
    contents.pop()
    num_versions = num_versions-1

    response = client.delete_object(Bucket=bucket_name, Key=key, VersionId=removed_version_id)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, contents[-1])

    # add a delete marker
    response = client.delete_object(Bucket=bucket_name, Key=key)
    eq(response['DeleteMarker'], True)

    delete_marker_version_id = response['VersionId']
    version_ids.append(delete_marker_version_id)

    response = client.list_object_versions(Bucket=bucket_name)
    eq(len(response['Versions']), num_versions)
    eq(len(response['DeleteMarkers']), 1)
    eq(response['DeleteMarkers'][0]['VersionId'], delete_marker_version_id)

    clean_up_bucket(client, bucket_name, key, version_ids)

@attr(resource='object')
@attr(method='create')
@attr(operation='create object, then switch to versioning')
@attr(assertion='behaves correctly')
@attr('versioning')
def test_versioning_obj_plain_null_version_removal():
    bucket_name = get_new_bucket()
    check_versioning(bucket_name, None)

    client = get_client()
    key = 'testobjfoo'
    content = 'fooz'
    client.put_object(Bucket=bucket_name, Key=key, Body=content)

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    client.delete_object(Bucket=bucket_name, Key=key, VersionId='null')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

@attr(resource='object')
@attr(method='create')
@attr(operation='create object, then switch to versioning')
@attr(assertion='behaves correctly')
@attr('versioning')
def test_versioning_obj_plain_null_version_overwrite():
    bucket_name = get_new_bucket()
    check_versioning(bucket_name, None)

    client = get_client()
    key = 'testobjfoo'
    content = 'fooz'
    client.put_object(Bucket=bucket_name, Key=key, Body=content)

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    content2 = 'zzz'
    response = client.put_object(Bucket=bucket_name, Key=key, Body=content2)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, content2)

    version_id = response['VersionId']
    client.delete_object(Bucket=bucket_name, Key=key, VersionId=version_id)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, content)

    client.delete_object(Bucket=bucket_name, Key=key, VersionId='null')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

@attr(resource='object')
@attr(method='create')
@attr(operation='create object, then switch to versioning')
@attr(assertion='behaves correctly')
@attr('versioning')
def test_versioning_obj_plain_null_version_overwrite_suspended():
    bucket_name = get_new_bucket()
    check_versioning(bucket_name, None)

    client = get_client()
    key = 'testobjbar'
    content = 'foooz'
    client.put_object(Bucket=bucket_name, Key=key, Body=content)

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    check_configure_versioning_retry(bucket_name, "Suspended", "Suspended")

    content2 = 'zzz'
    response = client.put_object(Bucket=bucket_name, Key=key, Body=content2)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, content2)

    response = client.list_object_versions(Bucket=bucket_name)
    # original object with 'null' version id still counts as a version
    eq(len(response['Versions']), 1)

    client.delete_object(Bucket=bucket_name, Key=key, VersionId='null')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

def delete_suspended_versioning_obj(client, bucket_name, key, version_ids, contents):
    client.delete_object(Bucket=bucket_name, Key=key)

    # clear out old null objects in lists since they will get overwritten
    eq(len(version_ids), len(contents))
    i = 0
    for version_id in version_ids:
        if version_id == 'null':
            version_ids.pop(i)
            contents.pop(i)
        i += 1

    return (version_ids, contents)

def overwrite_suspended_versioning_obj(client, bucket_name, key, version_ids, contents, content):
    client.put_object(Bucket=bucket_name, Key=key, Body=content)

    # clear out old null objects in lists since they will get overwritten
    eq(len(version_ids), len(contents))
    i = 0
    for version_id in version_ids:
        if version_id == 'null':
            version_ids.pop(i)
            contents.pop(i)
        i += 1

    # add new content with 'null' version id to the end
    contents.append(content)
    version_ids.append('null')

    return (version_ids, contents)


@attr(resource='object')
@attr(method='create')
@attr(operation='suspend versioned bucket')
@attr(assertion='suspended versioning behaves correctly')
@attr('versioning')
def test_versioning_obj_suspend_versions():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'testobj'
    num_versions = 5

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    check_configure_versioning_retry(bucket_name, "Suspended", "Suspended")

    delete_suspended_versioning_obj(client, bucket_name, key, version_ids, contents)
    delete_suspended_versioning_obj(client, bucket_name, key, version_ids, contents)

    overwrite_suspended_versioning_obj(client, bucket_name, key, version_ids, contents, 'null content 1')
    overwrite_suspended_versioning_obj(client, bucket_name, key, version_ids, contents, 'null content 2')
    delete_suspended_versioning_obj(client, bucket_name, key, version_ids, contents)
    overwrite_suspended_versioning_obj(client, bucket_name, key, version_ids, contents, 'null content 3')
    delete_suspended_versioning_obj(client, bucket_name, key, version_ids, contents)

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, 3, version_ids, contents)
    num_versions += 3

    for idx in range(num_versions):
        remove_obj_version(client, bucket_name, key, version_ids, contents, idx)

    eq(len(version_ids), 0)
    eq(len(version_ids), len(contents))

@attr(resource='object')
@attr(method='remove')
@attr(operation='create and remove versions')
@attr(assertion='everything works')
@attr('versioning')
def test_versioning_obj_create_versions_remove_all():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'testobj'
    num_versions = 10

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)
    for idx in range(num_versions):
        remove_obj_version(client, bucket_name, key, version_ids, contents, idx)

    eq(len(version_ids), 0)
    eq(len(version_ids), len(contents))

@attr(resource='object')
@attr(method='remove')
@attr(operation='create and remove versions')
@attr(assertion='everything works')
@attr('versioning')
def test_versioning_obj_create_versions_remove_special_names():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    keys = ['_testobj', '_', ':', ' ']
    num_versions = 10

    for key in keys:
        (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)
        for idx in range(num_versions):
            remove_obj_version(client, bucket_name, key, version_ids, contents, idx)

        eq(len(version_ids), 0)
        eq(len(version_ids), len(contents))

@attr(resource='object')
@attr(method='multipart')
@attr(operation='create and test multipart object')
@attr(assertion='everything works')
@attr('versioning')
def test_versioning_obj_create_overwrite_multipart():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'testobj'
    num_versions = 3
    contents = []
    version_ids = []

    for i in range(num_versions):
        ret =  _do_test_multipart_upload_contents(bucket_name, key, 3)
        contents.append(ret)

    response = client.list_object_versions(Bucket=bucket_name)
    for version in response['Versions']:
        version_ids.append(version['VersionId'])

    version_ids.reverse()
    check_obj_versions(client, bucket_name, key, version_ids, contents)

    for idx in range(num_versions):
        remove_obj_version(client, bucket_name, key, version_ids, contents, idx)

    eq(len(version_ids), 0)
    eq(len(version_ids), len(contents))

@attr(resource='object')
@attr(method='multipart')
@attr(operation='list versioned objects')
@attr(assertion='everything works')
@attr('versioning')
def test_versioning_obj_list_marker():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'testobj'
    key2 = 'testobj-1'
    num_versions = 5

    contents = []
    version_ids = []
    contents2 = []
    version_ids2 = []

    # for key #1
    for i in range(num_versions):
        body = 'content-{i}'.format(i=i)
        response = client.put_object(Bucket=bucket_name, Key=key, Body=body)
        version_id = response['VersionId']

        contents.append(body)
        version_ids.append(version_id)

    # for key #2
    for i in range(num_versions):
        body = 'content-{i}'.format(i=i)
        response = client.put_object(Bucket=bucket_name, Key=key2, Body=body)
        version_id = response['VersionId']

        contents2.append(body)
        version_ids2.append(version_id)

    response = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    # obj versions in versions come out created last to first not first to last like version_ids & contents
    versions.reverse()

    i = 0
    # test the last 5 created objects first
    for i in range(5):
        version = versions[i]
        eq(version['VersionId'], version_ids2[i])
        eq(version['Key'], key2)
        check_obj_content(client, bucket_name, key2, version['VersionId'], contents2[i])
        i += 1

    # then the first 5
    for j in range(5):
        version = versions[i]
        eq(version['VersionId'], version_ids[j])
        eq(version['Key'], key)
        check_obj_content(client, bucket_name, key, version['VersionId'], contents[j])
        i += 1

@attr(resource='object')
@attr(method='multipart')
@attr(operation='create and test versioned object copying')
@attr(assertion='everything works')
@attr('versioning')
def test_versioning_copy_obj_version():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'testobj'
    num_versions = 3

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    for i in range(num_versions):
        new_key_name = 'key_{i}'.format(i=i)
        copy_source = {'Bucket': bucket_name, 'Key': key, 'VersionId': version_ids[i]}
        client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key=new_key_name)
        response = client.get_object(Bucket=bucket_name, Key=new_key_name)
        body = _get_body(response)
        eq(body, contents[i])

    another_bucket_name = get_new_bucket()

    for i in range(num_versions):
        new_key_name = 'key_{i}'.format(i=i)
        copy_source = {'Bucket': bucket_name, 'Key': key, 'VersionId': version_ids[i]}
        client.copy_object(Bucket=another_bucket_name, CopySource=copy_source, Key=new_key_name)
        response = client.get_object(Bucket=another_bucket_name, Key=new_key_name)
        body = _get_body(response)
        eq(body, contents[i])

    new_key_name = 'new_key'
    copy_source = {'Bucket': bucket_name, 'Key': key}
    client.copy_object(Bucket=another_bucket_name, CopySource=copy_source, Key=new_key_name)

    response = client.get_object(Bucket=another_bucket_name, Key=new_key_name)
    body = _get_body(response)
    eq(body, contents[-1])

@attr(resource='object')
@attr(method='delete')
@attr(operation='delete multiple versions')
@attr(assertion='deletes multiple versions of an object with a single call')
@attr('versioning')
def test_versioning_multi_object_delete():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'key'
    num_versions = 2

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    response = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    versions.reverse()

    for version in versions:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=version['VersionId'])

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

    # now remove again, should all succeed due to idempotency
    for version in versions:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=version['VersionId'])

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

@attr(resource='object')
@attr(method='delete')
@attr(operation='delete multiple versions')
@attr(assertion='deletes multiple versions of an object and delete marker with a single call')
@attr('versioning')
def test_versioning_multi_object_delete_with_marker():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'key'
    num_versions = 2

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    client.delete_object(Bucket=bucket_name, Key=key)
    response = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    delete_markers = response['DeleteMarkers']

    version_ids.append(delete_markers[0]['VersionId'])
    eq(len(version_ids), 3)
    eq(len(delete_markers), 1)

    for version in versions:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=version['VersionId'])

    for delete_marker in delete_markers:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=delete_marker['VersionId'])

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)
    eq(('DeleteMarkers' in response), False)

    for version in versions:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=version['VersionId'])

    for delete_marker in delete_markers:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=delete_marker['VersionId'])

    # now remove again, should all succeed due to idempotency
    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)
    eq(('DeleteMarkers' in response), False)

def _do_create_object(client, bucket_name, key, i):
    body = 'data {i}'.format(i=i)
    client.put_object(Bucket=bucket_name, Key=key, Body=body)

def _do_remove_ver(client, bucket_name, key, version_id):
    client.delete_object(Bucket=bucket_name, Key=key, VersionId=version_id)

def _do_create_versioned_obj_concurrent(client, bucket_name, key, num):
    t = []
    for i in range(num):
        thr = threading.Thread(target = _do_create_object, args=(client, bucket_name, key, i))
        thr.start()
        t.append(thr)
    return t

def _do_clear_versioned_bucket_concurrent(client, bucket_name):
    t = []
    response = client.list_object_versions(Bucket=bucket_name)
    for version in response.get('Versions', []):
        thr = threading.Thread(target = _do_remove_ver, args=(client, bucket_name, version['Key'], version['VersionId']))
        thr.start()
        t.append(thr)
    return t

def _do_wait_completion(t):
    for thr in t:
        thr.join()

@attr(resource='object')
@attr(method='put')
@attr(operation='concurrent creation of objects, concurrent removal')
@attr(assertion='works')
# TODO: remove fails_on_rgw when https://tracker.ceph.com/issues/39142 is resolved
@attr('fails_on_rgw')
@attr('versioning')
def test_versioned_concurrent_object_create_concurrent_remove():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'myobj'
    num_versions = 5

    for i in range(5):
        t = _do_create_versioned_obj_concurrent(client, bucket_name, key, num_versions)
        _do_wait_completion(t)

        response = client.list_object_versions(Bucket=bucket_name)
        versions = response['Versions']

        eq(len(versions), num_versions)

        t = _do_clear_versioned_bucket_concurrent(client, bucket_name)
        _do_wait_completion(t)

        response = client.list_object_versions(Bucket=bucket_name)
        eq(('Versions' in response), False)

@attr(resource='object')
@attr(method='put')
@attr(operation='concurrent creation and removal of objects')
@attr(assertion='works')
@attr('versioning')
def test_versioned_concurrent_object_create_and_remove():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'myobj'
    num_versions = 3

    all_threads = []

    for i in range(3):

        t = _do_create_versioned_obj_concurrent(client, bucket_name, key, num_versions)
        all_threads.append(t)

        t = _do_clear_versioned_bucket_concurrent(client, bucket_name)
        all_threads.append(t)

    for t in all_threads:
        _do_wait_completion(t)

    t = _do_clear_versioned_bucket_concurrent(client, bucket_name)
    _do_wait_completion(t)

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config')
@attr('lifecycle')
def test_lifecycle_set():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Days': 1}, 'Prefix': 'test1/', 'Status':'Enabled'},
           {'ID': 'rule2', 'Expiration': {'Days': 2}, 'Prefix': 'test2/', 'Status':'Disabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='get lifecycle config no id')
@attr('lifecycle')
def test_lifecycle_get_no_id():
    bucket_name = get_new_bucket()
    client = get_client()

    rules=[{'Expiration': {'Days': 31}, 'Prefix': 'test1/', 'Status':'Enabled'},
           {'Expiration': {'Days': 120}, 'Prefix': 'test2/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    response = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    current_lc = response['Rules']

    Rule = namedtuple('Rule',['prefix','status','days'])
    rules = {'rule1' : Rule('test1/','Enabled',31),
             'rule2' : Rule('test2/','Enabled',120)}

    for lc_rule in current_lc:
        if lc_rule['Prefix'] == rules['rule1'].prefix:
            eq(lc_rule['Expiration']['Days'], rules['rule1'].days)
            eq(lc_rule['Status'], rules['rule1'].status)
            assert 'ID' in lc_rule
        elif lc_rule['Prefix'] == rules['rule2'].prefix:
            eq(lc_rule['Expiration']['Days'], rules['rule2'].days)
            eq(lc_rule['Status'], rules['rule2'].status)
            assert 'ID' in lc_rule
        else:
            # neither of the rules we supplied was returned, something wrong
            print("rules not right")
            assert False

@attr(resource='bucket')
@attr(method='put')
@attr(operation='id too long in lifecycle rule')
@attr('lifecycle')
@attr(assertion='fails 400')
def test_lifecycle_id_too_long():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 256*'a', 'Expiration': {'Days': 2}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}

    e = assert_raises(ClientError, client.put_bucket_lifecycle_configuration, Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidArgument')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='same id')
@attr('lifecycle')
@attr(assertion='fails 400')
def test_lifecycle_same_id():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Days': 1}, 'Prefix': 'test1/', 'Status':'Enabled'},
           {'ID': 'rule1', 'Expiration': {'Days': 2}, 'Prefix': 'test2/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}

    e = assert_raises(ClientError, client.put_bucket_lifecycle_configuration, Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidArgument')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with expiration date')
@attr('lifecycle')
def test_lifecycle_set_date():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Date': '2017-09-27'}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}

    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with not iso8601 date')
@attr('lifecycle')
@attr(assertion='fails 400')
def test_lifecycle_set_invalid_date():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Date': '20200101'}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}

    e = assert_raises(ClientError, client.put_bucket_lifecycle_configuration, Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

def setup_lifecycle_expiration(client, bucket_name, rule_id, delta_days,
                                    rule_prefix):
    rules=[{'ID': rule_id,
            'Expiration': {'Days': delta_days}, 'Prefix': rule_prefix,
            'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(
        Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    key = rule_prefix + '/foo'
    body = 'bar'
    response = client.put_object(Bucket=bucket_name, Key=key, Body=body)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)
    response = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    return response

def check_lifecycle_expiration_header(response, start_time, rule_id,
                                      delta_days):
    print(response)
    #TODO: see how this can work
    #print(response['ResponseMetadata']['HTTPHeaders'])
    #exp_header = response['ResponseMetadata']['HTTPHeaders']['x-amz-expiration']
    #m = re.search(r'expiry-date="(.+)", rule-id="(.+)"', exp_header)

    #expiration = datetime.datetime.strptime(m.group(1),
    #                                        '%a %b %d %H:%M:%S %Y')
    #eq((expiration - start_time).days, delta_days)
    #eq(m.group(2), rule_id)

    return True

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with noncurrent version expiration')
@attr('lifecycle')
def test_lifecycle_set_noncurrent():
    bucket_name = _create_objects(keys=['past/foo', 'future/bar'])
    client = get_client()
    rules=[{'ID': 'rule1', 'NoncurrentVersionExpiration': {'NoncurrentDays': 2}, 'Prefix': 'past/', 'Status':'Enabled'},
           {'ID': 'rule2', 'NoncurrentVersionExpiration': {'NoncurrentDays': 3}, 'Prefix': 'future/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with delete marker expiration')
@attr('lifecycle')
def test_lifecycle_set_deletemarker():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'ExpiredObjectDeleteMarker': True}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with Filter')
@attr('lifecycle')
def test_lifecycle_set_filter():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'ExpiredObjectDeleteMarker': True}, 'Filter': {'Prefix': 'foo'}, 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with empty Filter')
@attr('lifecycle')
def test_lifecycle_set_empty_filter():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'ExpiredObjectDeleteMarker': True}, 'Filter': {}, 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

def _test_encryption_sse_customer_write(file_size):
    """
    Tests Create a file of A's, use it to set_contents_from_file.
    Create a file of B's, use it to re-set_contents_from_file.
    Re-read the contents, and confirm we get B's
    """
    bucket_name = get_new_bucket()
    client = get_client()
    key = 'testobj'
    data = 'A'*file_size
    sse_client_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw=='
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key=key, Body=data)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.GetObject', lf)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, data)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='Test Bucket Policy')
@attr(assertion='succeeds')
@attr('bucket-policy')
def test_bucket_policy():
    bucket_name = get_new_bucket()
    client = get_client()
    key = 'asdf'
    client.put_object(Bucket=bucket_name, Key=key, Body='asdf')

    resource1 = "arn:aws:s3:::" + bucket_name
    resource2 = "arn:aws:s3:::" + bucket_name + "/*"
    policy_document = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "s3:ListBucket",
        "Resource": [
            "{}".format(resource1),
            "{}".format(resource2)
          ]
        }]
     })

    client.put_bucket_policy(Bucket=bucket_name, Policy=policy_document)

    alt_client = get_alt_client()
    response = alt_client.list_objects(Bucket=bucket_name)
    eq(len(response['Contents']), 1)

@attr('bucket-policy')
@attr('list-objects-v2')
def test_bucketv2_policy():
    bucket_name = get_new_bucket()
    client = get_client()
    key = 'asdf'
    client.put_object(Bucket=bucket_name, Key=key, Body='asdf')

    resource1 = "arn:aws:s3:::" + bucket_name
    resource2 = "arn:aws:s3:::" + bucket_name + "/*"
    policy_document = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "s3:ListBucket",
        "Resource": [
            "{}".format(resource1),
            "{}".format(resource2)
          ]
        }]
     })

    client.put_bucket_policy(Bucket=bucket_name, Policy=policy_document)

    alt_client = get_alt_client()
    response = alt_client.list_objects_v2(Bucket=bucket_name)
    eq(len(response['Contents']), 1)

def _create_simple_tagset(count):
    tagset = []
    for i in range(count):
        tagset.append({'Key': str(i), 'Value': str(i)})

    return {'TagSet': tagset}

def _make_random_string(size):
    return ''.join(random.choice(string.ascii_letters) for _ in range(size))


@attr(resource='object')
@attr(method='get')
@attr(operation='Test Get/PutObjTagging output')
@attr(assertion='success')
@attr('tagging')
def test_get_obj_tagging():
    key = 'testputtags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    input_tagset = _create_simple_tagset(2)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])


@attr(resource='object')
@attr(method='get')
@attr(operation='Test HEAD obj tagging output')
@attr(assertion='success')
@attr('tagging')
def test_get_obj_head_tagging():
    key = 'testputtags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()
    count = 2

    input_tagset = _create_simple_tagset(count)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.head_object(Bucket=bucket_name, Key=key)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)
    eq(response['ResponseMetadata']['HTTPHeaders']['x-amz-tagging-count'], str(count))

@attr(resource='object')
@attr(method='get')
@attr(operation='Test Put max allowed tags')
@attr(assertion='success')
@attr('tagging')
def test_put_max_tags():
    key = 'testputmaxtags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    input_tagset = _create_simple_tagset(10)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])

@attr(resource='object')
@attr(method='get')
@attr(operation='Test Put max allowed k-v size')
@attr(assertion='success')
@attr('tagging')
def test_put_max_kvsize_tags():
    key = 'testputmaxkeysize'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    tagset = []
    for i in range(10):
        k = _make_random_string(128)
        v = _make_random_string(256)
        tagset.append({'Key': k, 'Value': v})

    input_tagset = {'TagSet': tagset}

    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    for kv_pair in response['TagSet']:
        eq((kv_pair in input_tagset['TagSet']), True)

@attr(resource='object')
@attr(method='get')
@attr(operation='Test exceed key size')
@attr(assertion='success')
@attr('tagging')
def test_put_excess_key_tags():
    key = 'testputexcesskeytags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    tagset = []
    for i in range(10):
        k = _make_random_string(129)
        v = _make_random_string(256)
        tagset.append({'Key': k, 'Value': v})

    input_tagset = {'TagSet': tagset}

    e = assert_raises(ClientError, client.put_object_tagging, Bucket=bucket_name, Key=key, Tagging=input_tagset)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidTag')

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(len(response['TagSet']), 0)

@attr(resource='object')
@attr(method='get')
@attr(operation='Test exceed val size')
@attr(assertion='success')
@attr('tagging')
def test_put_excess_val_tags():
    key = 'testputexcesskeytags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    tagset = []
    for i in range(10):
        k = _make_random_string(128)
        v = _make_random_string(257)
        tagset.append({'Key': k, 'Value': v})

    input_tagset = {'TagSet': tagset}

    e = assert_raises(ClientError, client.put_object_tagging, Bucket=bucket_name, Key=key, Tagging=input_tagset)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidTag')

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(len(response['TagSet']), 0)

@attr(resource='object')
@attr(method='get')
@attr(operation='Test PUT modifies existing tags')
@attr(assertion='success')
@attr('tagging')
def test_put_modify_tags():
    key = 'testputmodifytags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    tagset = []
    tagset.append({'Key': 'key', 'Value': 'val'})
    tagset.append({'Key': 'key2', 'Value': 'val2'})

    input_tagset = {'TagSet': tagset}

    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])

    tagset2 = []
    tagset2.append({'Key': 'key3', 'Value': 'val3'})

    input_tagset2 = {'TagSet': tagset2}

    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset2)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset2['TagSet'])

@attr(resource='object')
@attr(method='get')
@attr(operation='Test Delete tags')
@attr(assertion='success')
@attr('tagging')
def test_put_delete_tags():
    key = 'testputmodifytags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    input_tagset = _create_simple_tagset(2)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])

    response = client.delete_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 204)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(len(response['TagSet']), 0)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr('tagging')
@attr(assertion='succeeds and returns written data')
def test_post_object_tags_authenticated_request():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [
    {"bucket": bucket_name},
        ["starts-with", "$key", "foo"],
        {"acl": "private"},
        ["starts-with", "$Content-Type", "text/plain"],
        ["content-length-range", 0, 1024],
        ["starts-with", "$tagging", ""]
    ]}

    # xml_input_tagset is the same as `input_tagset = _create_simple_tagset(2)` in xml
    # There is not a simple way to change input_tagset to xml like there is in the boto2 tetss
    xml_input_tagset = "<Tagging><TagSet><Tag><Key>0</Key><Value>0</Value></Tag><Tag><Key>1</Key><Value>1</Value></Tag></TagSet></Tagging>"

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([
        ("key" , "foo.txt"),
        ("AWSAccessKeyId" , aws_access_key_id),\
        ("acl" , "private"),("signature" , signature),("policy" , policy),\
        ("tagging", xml_input_tagset),
        ("Content-Type" , "text/plain"),
        ('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, 'bar')


@attr(resource='object')
@attr(method='put')
@attr(operation='Test PutObj with tagging headers')
@attr(assertion='success')
@attr('tagging')
def test_put_obj_with_tags():
    bucket_name = get_new_bucket()
    client = get_client()
    key = 'testtagobj1'
    data = 'A'*100

    tagset = []
    tagset.append({'Key': 'bar', 'Value': ''})
    tagset.append({'Key': 'foo', 'Value': 'bar'})

    put_obj_tag_headers = {
        'x-amz-tagging' : 'foo=bar&bar'
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(put_obj_tag_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)

    client.put_object(Bucket=bucket_name, Key=key, Body=data)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, data)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    response_tagset = response['TagSet']
    tagset = tagset
    eq(response_tagset, tagset)

def _make_arn_resource(path="*"):
    return "arn:aws:s3:::{}".format(path)

@attr(resource='object')
@attr(method='get')
@attr(operation='Test GetObjTagging public read')
@attr(assertion='success')
@attr('tagging')
@attr('bucket-policy')
def test_get_tags_acl_public():
    key = 'testputtagsacl'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    resource = _make_arn_resource("{}/{}".format(bucket_name, key))
    policy_document = make_json_policy("s3:GetObjectTagging",
                                       resource)

    client.put_bucket_policy(Bucket=bucket_name, Policy=policy_document)

    input_tagset = _create_simple_tagset(10)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    alt_client = get_alt_client()

    response = alt_client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])

@attr(resource='object')
@attr(method='get')
@attr(operation='Test PutObjTagging public wrote')
@attr(assertion='success')
@attr('tagging')
@attr('bucket-policy')
def test_put_tags_acl_public():
    key = 'testputtagsacl'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    resource = _make_arn_resource("{}/{}".format(bucket_name, key))
    policy_document = make_json_policy("s3:PutObjectTagging",
                                       resource)

    client.put_bucket_policy(Bucket=bucket_name, Policy=policy_document)

    input_tagset = _create_simple_tagset(10)
    alt_client = get_alt_client()
    response = alt_client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])

@attr(resource='object')
@attr(method='get')
@attr(operation='test deleteobjtagging public')
@attr(assertion='success')
@attr('tagging')
@attr('bucket-policy')
def test_delete_tags_obj_public():
    key = 'testputtagsacl'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    resource = _make_arn_resource("{}/{}".format(bucket_name, key))
    policy_document = make_json_policy("s3:DeleteObjectTagging",
                                       resource)

    client.put_bucket_policy(Bucket=bucket_name, Policy=policy_document)

    input_tagset = _create_simple_tagset(10)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    alt_client = get_alt_client()

    response = alt_client.delete_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 204)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(len(response['TagSet']), 0)
