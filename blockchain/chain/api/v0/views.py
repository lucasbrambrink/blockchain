# from snippets.models import Snippet
from rest_framework.permissions import AllowAny
from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response
from .serializers import BlockSerializer, Block, ChainSerializer, Chain, Peer, PeerSerializer


class BlockApiView(generics.RetrieveAPIView):
    permission_classes = (AllowAny,)
    serializer_class = BlockSerializer
    queryset = Block.objects.all()
    lookup_field = 'hash'


class BlockCreateView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = BlockSerializer

    def create(self, request, *args, **kwargs):
        serializer = BlockSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        block = Block(**serializer.validated_data)
        block.chain, _ = Chain.objects.get_or_create(name=kwargs.get('chain_name'))
        if not block.chain.is_valid_next_block(block):
            return Response({}, status=status.HTTP_304_NOT_MODIFIED)

        block.save()
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class LatestBlockApiView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = BlockSerializer

    def get(self, request, *args, **kwargs):
        instance = Block.objects\
            .filter(chain__name=kwargs.get('chain_name'))\
            .order_by('index')\
            .last()
        return Response(BlockSerializer(instance).data,
                        status=status.HTTP_200_OK)


class ChainApiView(generics.RetrieveAPIView):
    permission_classes = (AllowAny,)
    serializer_class = ChainSerializer
    queryset = Chain.objects.all()
    lookup_field = 'name'


class PeerApiView(generics.ListAPIView,
                  generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = PeerSerializer
    queryset = Peer.objects.all()



