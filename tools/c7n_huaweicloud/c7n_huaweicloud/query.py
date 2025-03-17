# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging
import jmespath

from c7n.actions import ActionRegistry
from c7n.filters import FilterRegistry
from c7n.manager import ResourceManager
from c7n.query import sources, MaxResourceLimit
from c7n.utils import local_session

log = logging.getLogger('custodian.huaweicloud.query')


class ResourceQuery:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    def filter(self, resource_manager, **params):
        m = resource_manager.resource_type
        session = local_session(self.session_factory)
        client = session.client(m.service)
        request = session.request(m.service)

        enum_op, path, extra_args = m.enum_spec
        response = self._invoke_client_enum(client, enum_op, request)
        resources = jmespath.search(path, eval(
            str(response).replace('null', 'None').replace('false', 'False').replace('true', 'True')))
        return resources

    def _invoke_client_enum(self, client, enum_op, request):
        return getattr(client, enum_op)(request)


@sources.register('describe-huaweicloud')
class DescribeSource:
    def __init__(self, manager):
        self.manager = manager
        self.query = ResourceQuery(manager.session_factory)

    def get_resources(self, query):
        if query is None:
            query = {}
        return self.query.filter(self.manager, **query)

    def get_permissions(self):
        return ()

    def augment(self, resources):
        return resources


class QueryMeta(type):
    """metaclass to have consistent action/filter registry for new resources."""
    def __new__(cls, name, parents, attrs):
        if 'filter_registry' not in attrs:
            attrs['filter_registry'] = FilterRegistry(
                '%s.filters' % name.lower())
        if 'action_registry' not in attrs:
            attrs['action_registry'] = ActionRegistry(
                '%s.actions' % name.lower())

        return super(QueryMeta, cls).__new__(cls, name, parents, attrs)


class QueryResourceManager(ResourceManager, metaclass=QueryMeta):

    source_mapping = sources

    def __init__(self, ctx, data):
        super(QueryResourceManager, self).__init__(ctx, data)
        self.source = self.get_source(self.source_type)

    def get_permissions(self):
        return ()

    def get_source(self, source_type):
        if source_type in self.source_mapping:
            return self.source_mapping.get(source_type)(self)
        if source_type in sources:
            return sources[source_type](self)
        raise KeyError("Invalid Source %s" % source_type)

    def get_client(self):
        session = local_session(self.session_factory)
        client = session.client(self.resource_type.service)
        return client

    def get_model(self):
        return self.resource_type

    def get_cache_key(self, query):
        return {'source_type': self.source_type,
                'query': query,
                'service': self.resource_type.service}

    def get_resource(self, resource_info):
        return self.resource_type.get(self.get_client(), resource_info)

    @property
    def source_type(self):
        return self.data.get('source', 'describe-huaweicloud')

    def get_resource_query(self):
        if 'query' in self.data:
            return {'filter': self.data.get('query')}

    def resources(self, query=None):
        q = query or self.get_resource_query()
        key = self.get_cache_key(q)
        resources = None
        if self._cache.load():
            resources = self._cache.get(key)
            if resources:
                self.log.debug(
                    "Using cached %s: %d"
                    % (
                        "%s.%s" % (self.__class__.__module__, self.__class__.__name__),
                        len(resources),
                    )
                )
        if resources is None:
            resources = self._fetch_resources(q)
            self._cache.save(key, resources)

        resource_count = len(resources)
        resources = self.filter_resources(resources)

        # Check if we're out of a policies execution limits.
        if self.data == self.ctx.policy.data:
            self.check_resource_limit(len(resources), resource_count)
        return resources

    def check_resource_limit(self, selection_count, population_count):
        """Check if policy's execution affects more resources then its limit.
        """
        p = self.ctx.policy
        max_resource_limits = MaxResourceLimit(p, selection_count, population_count)
        return max_resource_limits.check_resource_limits()

    def _fetch_resources(self, query):
        return self.augment(self.source.get_resources(query)) or []

    def augment(self, resources):
        return resources


class TypeMeta(type):
    def __repr__(cls):
        return "<TypeInfo service:%s>" % (
            cls.service)


class TypeInfo(metaclass=TypeMeta):
    service = None
