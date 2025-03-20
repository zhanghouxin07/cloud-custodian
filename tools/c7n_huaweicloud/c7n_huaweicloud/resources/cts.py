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
        enum_spec = ("list_trackers", "trackers", "offset")
        id = 'id'
        tag = True

@Cts.action_registry.register("add-tracker")
class CtsAddTracker(HuaweiCloudBaseAction):
    """Add Tracker.

    :Example:

    .. code-block:: yaml

    policies:
        - name: cts-test
          resource: huaweicloud.cts
          actions:
            - type: addTracker
              tracker_name: "system"
              tracker_type: "system"
    """

    schema = type_schema(
        "add-tracker",
        tracker_name={"type": "string"},
        tracker_type={"type": "string"}
    )

    def perform_action(self, resource):
        client = self.manager.get_client()
        properties = {
            "tracker_name": self.data.get("tracker_name", "system"),
            "tracker_type": self.data.get("tracker_type", "system")
        }
        request = CreateTrackerRequest()
        request.body = CreateTrackerRequestBody(
            tracker_name=properties["tracker_name"],
            tracker_type=properties["tracker_type"]
        )
        log.error("API req: %s", request)
        try:
            response = client.create_tracker(request)
            log.debug("API Response: %s", response)
        except exceptions.ClientRequestException as e:
            log.error(e.status_code, e.request_id, e.error_code, e.error_msg)
            raise
        return response

@Cts.action_registry.register("delete-tracker")
class CtsDeleteTracker(HuaweiCloudBaseAction):
    """Delete Tracker.

    :Example:

    .. code-block:: yaml

    policies:
        - name: delete-tracker
          resource: huaweicloud.cts
          actions:
            - type: delete-tracker
              tracker_name: "system"
              tracker_type: "system"
    """

    schema = type_schema(
        "delete-tracker",
        tracker_name={"type": "string"},
        tracker_type={"type": "string"}
    )

    def perform_action(self, resource):
        client = self.manager.get_client()
        properties = {
            "tracker_name": self.data.get("tracker_name", "system"),
            "tracker_type": self.data.get("tracker_type", "system")
        }

        request = DeleteTrackerRequest()
        request.tracker_name = properties["tracker_name"]
        request.tracker_type = properties["tracker_type"]
        try:
            response = client.delete_tracker(request)
        except exceptions.ClientRequestException as e:
            log.error(e.status_code, e.request_id, e.error_code, e.error_msg)
            raise
        return response

@Cts.action_registry.register("toggle-tracker")
class CtsToggleTracker(HuaweiCloudBaseAction):
    """Enable or Disable Tracker.

    :Example:

    .. code-block:: yaml

    policies:
        - name: toggle-tracker
          resource: huaweicloud.cts
          actions:
            - type: toggle-tracker
              tracker_name: "system"
              tracker_type: "system"
              status: "enabled"  # or "disabled"
    """

    schema = type_schema(
        "toggle-tracker",
        tracker_name={"type": "string"},
        tracker_type={"type": "string"},
        status={"type": "string", "enum": ["enabled", "disabled"]}
    )

    def perform_action(self, resource):
        client = self.manager.get_client()
        properties = {
            "tracker_name": self.data.get("tracker_name", "system"),
            "tracker_type": self.data.get("tracker_type", "system"),
            "status": self.data.get("status", "enabled")
        }

        request = UpdateTrackerRequest()
        request.body = UpdateTrackerRequestBody(
            status=properties["status"],
            tracker_name=properties["tracker_name"],
            tracker_type=properties["tracker_type"]
        )

        try:
            response = client.update_tracker(request)
        except exceptions.ClientRequestException as e:
            log.error(e.status_code, e.request_id, e.error_code, e.error_msg)
            raise
        return response

@Cts.action_registry.register("create-notification")
class CtsCreateNotification(HuaweiCloudBaseAction):
    """Create Critical Operation Notification.

    :Example:

    .. code-block:: yaml

    policies:
        - name: create-notification
          resource: huaweicloud.cts
          actions:
            - type: create-notification
              operation_type: "complete"
              notification_name: "test"
    """

    schema = type_schema(
        "create-notification",
        operation_type={"type": "string"},
        notification_name={"type": "string"}
    )

    def perform_action(self, resource):
        client = self.manager.get_client()
        properties = {
            "operation_type": self.data.get("operation_type", "complete"),
            "notification_name": self.data.get("notification_name", "defaultname")
        }

        request = CreateNotificationRequest()
        request.body = CreateNotificationRequestBody(
            operation_type=properties["operation_type"],
            notification_name=properties["notification_name"]
        )

        try:
            response = client.create_notification(request)
        except exceptions.ClientRequestException as e:
            log.error(e.status_code, e.request_id, e.error_code, e.error_msg)
            raise
        return response






