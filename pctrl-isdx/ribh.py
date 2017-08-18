#! /usr/bin/python
#
# in memory hash table rib

from collections import namedtuple

# have all the rib implementations return a consistent interface
labels = ('prefix', 'neighbor', 'next_hop', 'origin', 'as_path', 'communities', 'med', 'atomic_aggregate', 'asid')
RibTuple = namedtuple('RibTuple', labels)

class rib(object):
    def __init__(self, table_suffix, name):
        self.name = name + "_" + str(table_suffix)
        self.rib = {}

    def __del__(self):
        #self.cluster.shutdown()
        pass

    def __setitem__(self, key, item):
        self.add(item)

    def add(self, item):
        assert(isinstance(item, RibTuple))

        entry = {}
        for i,v in enumerate(labels):
            entry[v] = item[i]
        if item.prefix not in self.rib:
            self.rib[item.prefix] = {}
        self.rib[item.prefix][item.neighbor] = entry

    def get(self, **kwargs):
        assert 'prefix' in kwargs
        if kwargs['prefix'] not in self.rib:
            return None
        if 'neighbor' in kwargs:
            if kwargs['neighbor'] not in self.rib[kwargs['prefix']]:
                return None
            entry = self.rib[kwargs['prefix']][kwargs['neighbor']]
            return RibTuple(*[entry[l] for l in labels])
        else:
            entries = self.rib[kwargs['prefix']]
            for k, v in entries.iteritems():
                return RibTuple(*[v[l] for l in labels])
            return None

    def get_all(self, **kwargs):
        assert 'prefix' in kwargs

        if kwargs['prefix'] not in self.rib:
            return []
        entries = self.rib[kwargs['prefix']]
        ret = []
        for k, v in entries.iteritems():
            ret.append(RibTuple(*[v[l] for l in labels]))

        return ret

    def get_prefixes(self):
        output = [prefix for prefix in self.rib.keys()]
        return sorted(output)

    def update(self, names, item):
        assert names == 'prefix'

        self.rib[item.prefix] = {}
        entry = {}
        for i,v in enumerate(labels):
            entry[v] = item[i]
        self.rib[item.prefix][item.neighbor] = entry

    def delete(self, **kwargs):
        assert 'prefix' in kwargs
        if kwargs['prefix'] not in self.rib:
            return
        if 'neighbor' in kwargs:
            if kwargs['neighbor'] not in self.rib[kwargs['prefix']]:
                return
            del self.rib[kwargs['prefix']][kwargs['neighbor']]
        else:
            del self.rib[kwargs['prefix']]
