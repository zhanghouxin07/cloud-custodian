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

@resources.register('cts')
class Cts(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'cts'
        enum_spec = ("list_trackers", "cts", "offset")
        id = 'tracker_name'
        tag = True

@Cts.action_registry.register("query")
class CtsQuery(HuaweiCloudBaseAction):
    """Query cts server.

    :Example:

    .. code-block:: yaml

    policies:
        - name: query-ecs-tracker
          resource: huaweicloud.cts
          filters:
            - type: value
              key: tracker_name
              value: "your tracker name"
          actions:
            - type: query
              tracker_name: "trackerName"
              tracker_type: "system"
    """

    schema = type_schema(
        "query",
        tracker_name={"type": "string"},
        tracker_type={"type": "string"}
    )

    def perform_action(self, resource):
        client = self.manager.get_client()
        properties = {
            "tracker_name": self.data.get("tracker_name", "system"), 
            "tracker_type": self.data.get("tracker_type", "system")
        }
        request = ListTrackersRequest()
        request.tracker_name = properties["tracker_name"]
        request.tracker_type = properties["tracker_type"]
        try:
          response = client.list_trackers(request)
        except exceptions.ClientRequestException as e:
          log.error(e.status_code, e.request_id, e.error_code, e.error_msg)
          raise
        return response











