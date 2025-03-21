# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging

from boto3 import client
from huaweicloudsdkcts.v3 import *

from c7n.utils import type_schema
from c7n_huaweicloud.actions.base import HuaweiCloudBaseAction
from c7n_huaweicloud.provider import resources
from c7n_huaweicloud.query import QueryResourceManager, TypeInfo

log = logging.getLogger("custodian.huaweicloud.resources.cts")

@resources.register('cts-notification')
class Notification(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'cts-notification'
        enum_spec = ("list_notifications", "notifications", "offset")
        id = 'notification_id'
        tag = True
