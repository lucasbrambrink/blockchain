from django.db import models
from hashlib import sha256
import datetime
import logging
import pytz
import requests
from django.core.urlresolvers import reverse
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from .utils import SymmetricEncryption

log = logging.getLogger(__name__)

class Block(models.Model):
    time_stamp = models.DateTimeField(auto_now_add=False)
    index = models.IntegerField()
    data = models.TextField()
    hash = models.CharField(max_length=255)
    previous_hash = models.CharField(max_length=255)
    chain = models.ForeignKey(to='Chain')
    salt = models.CharField(max_length=255, default='')

    def __repr__(self):
        return '{}: {}'.format(self.index, str(self.hash)[:6])

    def __hash__(self):
        return sha256(
            u'{}{}{}{}{}'.format(
                self.time_stamp,
                self.index,
                self.data,
                self.previous_hash,
                self.salt).encode('utf-8'))\
            .hexdigest()

    @staticmethod
    def generate_next(latest_block, data):
        block = Block(
            data=data,
            index=latest_block.index + 1,
            time_stamp=datetime.datetime.now(tz=pytz.utc),
            previous_hash=latest_block.hash,
            salt=SymmetricEncryption.generate_salt(26)
        )
        while not block.valid_hash():
            block.salt = SymmetricEncryption.generate_salt(26)

        block.hash = block.__hash__()
        return block

    def is_valid_block(self, previous_block):
        if self.index != previous_block.index + 1:
            log.warning('%s: Invalid index: %s and %s' % (self.index, self.index, previous_block.index))
            return False
        if self.previous_hash != previous_block.hash:
            log.warning('%s: Invalid previous hash: %s and %s' % (self.index, self.hash, previous_block.hash))
            return False
        if self.__hash__() != self.hash:
            log.warning('%s: Invalid hash of content: %s and %s' % (self.index, self.hash, self.__hash__()))
            return False
        if not self.valid_hash():
            log.warning('%s: Invalid hash value: %s' % (self.index, self.hash))
            return False
        return True

    def valid_hash(self):
        return self.__hash__()[:5] == '00000'


class Chain(models.Model):
    time_stamp = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=255)

    def __len__(self):
        return self.block_set.count()

    def __repr__(self):
        return '{}: {}'.format(self.name, self.last_block)

    @property
    def last_block(self):
        return self.block_set.order_by('index').last()

    def create_seed(self):
        assert self.pk is not None
        seed = Block.generate_next(
            Block(hash=sha256('seed'.encode('utf-8')).hexdigest(),
                  index=-1),
            data='Seed data',
        )
        seed.chain = self
        seed.save()

    def is_valid_next_block(self, block):
        return block.is_valid_block(self.last_block)

    def add(self, data):
        if not self.block_set.count():
            self.create_seed()

        block = Block.generate_next(
            self.last_block,
            data
        )
        block.chain = self
        return block

    def is_valid_chain(self, blocks=None):
        blocks = blocks or list(self.block_set.order_by('index'))
        if not len(blocks):
            log.warning('Empty chain')
            return False
        if len(blocks) == 1 and blocks[0].index != 0:
            log.warning('Missing seed block in chain.')
            return False
        if not all(pblock.index + 1 == block.index == required_index
                   for pblock, block, required_index in zip(blocks[:-1], blocks[1:], range(1, len(blocks)))):
            log.warning('Chain is not sequential')
            return False
        return all(block.is_valid_block(pblock)
                   for pblock, block in zip(blocks[:-1], blocks[1:]))


    def replace_chain(self, new_chain):
        if self.is_valid_chain(new_chain) and len(new_chain) > len(self):
            self.block_set.all().delete()
            for block in new_chain:
                block.chain = self
                block.save()


class JsonApi(object):

    @classmethod
    def get(cls, base_url, api_url):
        url = '{}{}'.format(base_url, api_url)
        data = {}
        response = None
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            log.warning('GET failed: {} - {}'.format(url, exc))
            if response is not None and hasattr(response, 'content'):
                log.warning('RESPONSE {}'.format(response.content))
        finally:
            return data

    @classmethod
    def post(cls, base_url, api_url, data):
        url = '{}{}'.format(base_url, api_url)
        response_data = {}
        response = None
        try:
            response = requests.post(url, json=data)
            response.raise_for_status()
            if response.status_code == 201:
                log.info('Peer {} accepted block.'.format(base_url))
            if not len(response.content):
                if response.status_code == 304:
                    log.warning('Peer {}: unable to accept block.'.format(base_url))
            else:
                response_data = response.json()
        except Exception as exc:
            log.warning('POST failed: {} - {}'.format(url, exc))
            if response is not None and hasattr(response, 'content'):
                log.warning('RESPONSE {}'.format(response.content))
        finally:
            return response_data


class Peer(models.Model):
    name = models.CharField(max_length=255)
    address = models.CharField(max_length=255, unique=True)

    def __repr__(self):
        return '{}: {}'.format(self.name, self.address)

    def broadcast(self, chain_name, block):
        from .api.v0.serializers import BlockSerializer
        block_data = BlockSerializer(data=block.__dict__).as_json()
        for peer in Peer.objects.all():
            JsonApi.post(peer.address,
                         reverse('mine-block',
                                 kwargs={'chain_name': chain_name}),
                         data=block_data)

    def query_latest_block(self, chain_name):
        from .api.v0.serializers import BlockSerializer
        data = JsonApi.get(self.address,
                           reverse('latest-block',
                                   kwargs={'chain_name': chain_name}))
        serializer = BlockSerializer(data=data)
        serializer.is_valid()
        instance = Block(**serializer.validated_data)
        instance.chain = Chain.objects.get(name=chain_name)
        return instance

    def query_chain(self, chain_name):
        from .api.v0.serializers import BlockSerializer
        chain = Chain.objects.get(name=chain_name)
        data = JsonApi.get(self.address,
                           reverse('chain',
                                   kwargs={'name': chain_name}))

        blocks = []
        for block_data in data.get('block_set', []):
            serializer = BlockSerializer(data=block_data)
            if serializer.is_valid():
                block = Block(**serializer.validated_data)
                block.chain = chain
                blocks.append(block)

        return blocks

    def fetch_longest_chain(self, chain_name):
        chain = max(
            (peer.query_chain(chain_name)
             for peer in self.discover_all_peers()),
            key=len
        )
        return sorted(chain, key=lambda x: x.index)

    def mine_block(self, chain_name, data, password=None):
        chain = Chain.objects.get(name=chain_name)
        if password is not None:
            data = EncryptionApi.encrypt(password, data)
        new_block = chain.add(data)
        self.broadcast(chain_name, new_block)

    def synchronize(self, chain_name):
        self.discover_all_peers(commit=True)
        chain = Chain.objects.get(name=chain_name)
        longest_chain = self.fetch_longest_chain(chain_name)
        chain.replace_chain(longest_chain)

    def query_peers(self):
        from .api.v0.serializers import PeerSerializer
        data = JsonApi.get(self.address,
                           reverse('peers'))

        peers = []
        for peer in data:
            serializer = PeerSerializer(data=peer)
            if serializer.is_valid():
                peers.append(Peer(**serializer.validated_data))

        return peers

    @classmethod
    def scan_peers(cls, peers, known_peers):
        known_peers = set(p.address for p in known_peers)
        new_peers = []
        for peer in peers:
            foreign_peers = peer.query_peers()
            for fp in foreign_peers:
                if fp.address not in known_peers:
                    new_peers.append(fp)

        return new_peers

    @classmethod
    def discover_all_peers(cls, commit=False):
        discoveries = Peer.objects.all()
        known_peers = []
        while len(discoveries):
            known_peers.extend(discoveries)
            discoveries = cls.scan_peers(discoveries, known_peers)

        if commit:
            for peer in known_peers:
                peer.save()

        return known_peers


class EncryptionApi(object):

    @staticmethod
    def make_password(raw_password, salt):
        """10000 iterations of pbkdf2 and return only hash"""
        hasher = PBKDF2PasswordHasher()
        hashed_password = hasher.encode(raw_password, salt)
        return hashed_password.split('$').pop()

    @classmethod
    def encrypt(cls, raw_password, data):
        salt = SymmetricEncryption.generate_salt()
        password = cls.make_password(raw_password, salt)
        encryption_key = SymmetricEncryption.build_encryption_key(password)
        e_data = SymmetricEncryption.encrypt(encryption_key, data)
        return '{}${}'.format(salt, e_data.decode('utf-8'))

    @classmethod
    def decrypt(cls, raw_password, stored_data):
        salt, e_data = stored_data.split('$')
        password = cls.make_password(raw_password, salt)
        encryption_key = SymmetricEncryption.build_encryption_key(password)
        data = SymmetricEncryption.decrypt(encryption_key, e_data.encode('utf-8'))
        return data.decode('utf-8')

