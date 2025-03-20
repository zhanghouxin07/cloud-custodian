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

@resources.register('cts-tracker')
class Tracker(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'cts'
        enum_spec = ("list_trackers", "trackers", "offset")
        id = 'id'
        tag = True

@Tracker.action_registry.register("add-tracker")
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
        try:
            response = client.create_tracker(request)
        except exceptions.ClientRequestException as e:
            log.error(e.status_code, e.request_id, e.error_code, e.error_msg)
            raise
        return response

@Tracker.action_registry.register("delete-tracker")
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

@Tracker.action_registry.register("toggle-tracker")
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

@Tracker.action_registry.register("update-notification")
class CtsUpdateNotification(HuaweiCloudBaseAction):
    """Update CTS Notification.

    :Example:

    .. code-block:: yaml

    policies:
        - name: update-cts-notification
          resource: huaweicloud.cts-tracker
          actions:
            - type: update-notification
              notification_id: "938c9c8a-804b-4c61-bf7b-5e8b1793ae64"
              topic_id: "urn:smn:cn-east-2:932cb325cbca47a59ec1ea930ecc0f29:testcc"
              status: "enabled"
              notification_name: "keyOperate_info_zr1s"
              notify_user_list:
                - user_group: "zhanghouxin"
                  user_list:
                    - "zhanghouxin"
              operations:
                - service_type: "AAD"
                  resource_type: "addprotocolrule"
                  trace_names:
                    - "addProtocolRule"
    """

    schema = type_schema(
        "update-notification",
        notification_id={"type": "string"},
        topic_id={"type": "string"},
        status={"type": "string", "enum": ["enabled", "disabled"]},
        notification_name={"type": "string"},
        notify_user_list={"type": "array", "items": {
            "type": "object",
            "properties": {
                "user_group": {"type": "string"},
                "user_list": {"type": "array", "items": {"type": "string"}}
            }
        }},
        operations={"type": "array", "items": {
            "type": "object",
            "properties": {
                "service_type": {"type": "string"},
                "resource_type": {"type": "string"},
                "trace_names": {"type": "array", "items": {"type": "string"}}
            }
        }}
    )

    def perform_action(self, resource):
        client = self.manager.get_client()
        properties = {
            "notification_id": self.data.get("notification_id"),
            "topic_id": self.data.get("topic_id"),
            "status": self.data.get("status", "enabled"),
            "notification_name": self.data.get("notification_name"),
            "notify_user_list": self.data.get("notify_user_list", []),
            "operations": self.data.get("operations", [])
        }

        request = UpdateNotificationRequest()
        request.body = UpdateNotificationRequestBody(
            notification_id=properties["notification_id"],
            topic_id=properties["topic_id"],
            status=properties["status"],
            notification_name=properties["notification_name"],
            notify_user_list=[
                NotificationUsers(user_group=entry["user_group"], user_list=entry["user_list"])
                for entry in properties["notify_user_list"]
            ],
            operations=[
                Operations(
                    service_type=entry["service_type"],
                    resource_type=entry["resource_type"],
                    trace_names=entry["trace_names"]
                )
                for entry in properties["operations"]
            ],
            operation_type="customized"
        )

        try:
            response = client.update_notification(request)
            log.info(f"Successfully updated CTS notification: {response}")
        except exceptions.ClientRequestException as e:
            log.error(f"Error updating CTS notification: {e.status_code}, {e.request_id}, {e.error_code}, {e.error_msg}")
            raise
        return response

@Tracker.action_registry.register("set-trace-file-validation")
class CtsSetTraceFileValidation(HuaweiCloudBaseAction):
    """Set Trace File Validation.

    :Example:

    .. code-block:: yaml

    policies:
        - name: set-trace-file-validation
          resource: huaweicloud.cts-tracker
          actions:
            - type: set-trace-file-validation
              tracker_name: "system"
              tracker_type: "system"
              is_support_validate: true
              kms_id: "your-kms-id"
              is_support_trace_files_encryption: true
              obs_info:
                bucket_name: "sh2-gaochang1"
                compress_type: "gzip"
                is_sort_by_service: true
    """

    schema = type_schema(
        "set-trace-file-validation",
        tracker_name={"type": "string"},
        tracker_type={"type": "string"},
        is_support_validate={"type": "boolean"},
        kms_id={"type": "string"},
        is_support_trace_files_encryption={"type": "boolean"},
        obs_info={"type": "object", "properties": {
            "bucket_name": {"type": "string"},
            "compress_type": {"type": "string", "enum": ["gzip", "json", "none"]},
            "is_sort_by_service": {"type": "boolean"}
        }}
    )

    def perform_action(self, resource):
        client = self.manager.get_client()
        properties = {
            "tracker_name": self.data.get("tracker_name", "system"),
            "tracker_type": self.data.get("tracker_type", "system"),
            "is_support_validate": self.data.get("is_support_validate"),
            "kms_id": self.data.get("kms_id"),
            "is_support_trace_files_encryption": self.data.get("is_support_trace_files_encryption", True),
            "obs_info": self.data.get("obs_info", {})
        }

        request = UpdateTrackerRequest()
        request.body = UpdateTrackerRequestBody(
            is_support_validate=properties["is_support_validate"],
            kms_id=properties["kms_id"],
            is_support_trace_files_encryption=properties["is_support_trace_files_encryption"],
            obs_info=TrackerObsInfo(
                bucket_name=properties["obs_info"].get("bucket_name"),
                compress_type=properties["obs_info"].get("compress_type", "gzip"),
                is_sort_by_service=properties["obs_info"].get("is_sort_by_service", True)
            ),
            tracker_name=properties["tracker_name"],
            tracker_type=properties["tracker_type"]
        )

        try:
            response = client.update_tracker(request)
            log.info(f"Successfully updated trace file validation (is_support_validate={properties['is_support_validate']}) "
                     f"for tracker {properties['tracker_name']}.")
        except exceptions.ClientRequestException as e:
            log.error(f"Error updating trace file validation: {e.status_code}, {e.request_id}, {e.error_code}, {e.error_msg}")
            raise
        return response
