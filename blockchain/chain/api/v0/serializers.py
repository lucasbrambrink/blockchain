from rest_framework import serializers
from ...models import Block, Chain, Peer

import logging

log = logging.getLogger(__name__)


class BlockSerializer(serializers.ModelSerializer):

    class Meta:
        model = Block
        fields = ('hash', 'previous_hash', 'time_stamp', 'data', 'index')

    def as_json(self):
        self.is_valid()
        data = dict(self.validated_data)
        data['time_stamp'] = str(data['time_stamp'])
        return data



class ChainSerializer(serializers.ModelSerializer):
    block_set = BlockSerializer(many=True,
                                read_only=True,
                                allow_null=True)

    class Meta:
        model = Chain
        fields = ('name', 'block_set')


class PeerSerializer(serializers.ModelSerializer):

    class Meta:
        model = Peer
        fields = ('name', 'address',)