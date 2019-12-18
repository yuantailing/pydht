import argparse
import asyncio
import base64
import bencoder
import crcmod
import hashlib
import logging
import pprint
import secrets
import socket
import struct
import time


crc32c = crcmod.mkCrcFun(0x11EDC6F41, 0, True, 0xffffffff)

class Swarm:
    def __init__(self, swarm_id, is_node):
        self.id = swarm_id
        self.is_node = is_node
        self.buckets = [[] for _ in range(20 * 8 + 1)]
        self.id2node = dict()
        self.last_find_node = dict()
        self.last_get_peers = dict()
        self.last_announce_peer = dict()
        self.bad_nodes = dict()

    @staticmethod
    def same_bits(a, b):
        assert len(a) == len(b)  == 20
        res = 0
        for x, y in zip(a, b):
            z = x ^ y
            for i in range(7, -1, -1):
                if z & 2 ** i:
                    break
                else:
                    res += 1
            if z:
                break
        return res

    def add(self, id, addr):
        if id in self.id2node:
            self.update(id)
            return
        same = self.same_bits(self.id, id)
        entry = {'id': id, 'addr': addr, 'joined': time.time()}
        self.buckets[same].append(entry)
        self.id2node[id] = entry

    def is_valuable(self, id):
        if time.time() - self.bad_nodes.get(id, 0) < 60:
            return False
        same = self.same_bits(self.id, id)
        return len(self.buckets[same]) < 10 and \
            id not in self.id2node

    def update(self, id):
        if id in self.id2node:
            self.id2node[id]['updated'] = time.time()

    def nearest_nodes(self, target, K=8):
        # 可以做性能优化
        nodes = [node for bucket in self.buckets for node in bucket]
        nodes.sort(key=lambda node: Swarm.same_bits(node['id'], target))
        return nodes[-K:]

    def clean_bad_nodes(self, timeout):
        now = time.time()
        for bucket in self.buckets:
            for i in range(len(bucket) - 1, -1, -1):
                node = bucket[i]
                updated = max(node['joined'], node.get('updated', 0))
                if now > updated + timeout:
                    id = node['id']
                    logging.debug(f'remove node {node["addr"][0]}:{node["addr"][1]} from swarm, same_bits={self.same_bits(self.id, id)}')
                    bucket.pop(i)
                    if id in self.id2node:
                        self.id2node.pop(id)
                    self.bad_nodes[id] = time.time()

class DHT(asyncio.DatagramProtocol):
    class DHTProtocolError(Exception):
        pass

    def __init__(self):
        self.nodeid = self.secure_nodeid(secrets.token_bytes(20), '166.111.71.39') # TODO: get ip first
        self.bootstrap_nodes = BOOTSTRAP_NODES[:]
        self.find_node_protect = 5
        self.get_peers_protect = self.find_node_protect
        self.announce_peer_protect = 5
        self.service_swarm = Swarm(self.nodeid, True)
        self.swarms = [
            self.service_swarm, # 可有可无。有 service_swarm 的话是完整 DHT 实现，否则是只发出而不回复 find_node、get_peers 的“吸血鬼”
            Swarm(hashlib.sha1(b'test swarm 0021').digest(), False),
        ]
        self.info = dict()
        self.peers = dict()
        self.tokens = []

    def connection_made(self, transport):
        self.port = transport.get_extra_info('sockname')[1]
        logging.info(f'DHT server listening on {self.port}, nodeid is <{base64.b16encode(self.nodeid).decode().lower()}>')

        s = ', '.join(f'{node[0]}:{node[1]}' for node in self.bootstrap_nodes)
        logging.debug(f'bootstrap nodes: {s}')

        self.transport = transport
        for swarm in self.swarms:
            for addr in self.bootstrap_nodes:
                if swarm.is_node:
                    self.find_node_q(swarm, addr)
                else:
                    self.get_peers_q(swarm, addr)
        asyncio.ensure_future(self.ticking())

    def datagram_received(self, data, addr):
        try:
            obj = bencoder.bdecode(data)
            assert isinstance(obj, dict)
        except:
            logging.debug(f'cannot bdecode from {addr[0]}:{addr[1]}')
            return

        y = obj.get(b'y')
        t = obj.get(b't')
        v = obj.get(b'v')
        try:
            if y == b'r':
                r = obj.get(b'r')
                if not isinstance(r, dict):
                    raise self.DHTProtocolError('r is not a dict')
                id = r.get(b'id')
                if not isinstance(id, bytes) or len(id) != 20:
                    raise self.DHTProtocolError('malformed id')
                nodes = r.get(b'nodes')
                values = r.get(b'values')
                token = r.get(b'token')
                if t == b'fn':
                    self.find_node_t(id, nodes, addr)
                elif t == b'gp':
                    self.get_peers_t(id, nodes, values, token, addr)
                elif t == b'an':
                    self.announce_peer_t(id, addr)
                else:
                    raise self.DHTProtocolError('unknown transaction ID in r')
            elif y == b'q':
                if not isinstance(t, bytes):
                    raise self.DHTProtocolError('transaction ID is not bytes in q')
                q = obj.get(b'q')
                a = obj.get(b'a')
                if not isinstance(a, dict):
                    raise self.DHTProtocolError('a is not a dict')
                id = a.get(b'id')
                if not isinstance(id, bytes) or len(id) != 20:
                    raise self.DHTProtocolError('malformed id')
                if q == b'ping':
                    self.ping_r(id, t, addr)
                elif q == b'find_node':
                    target = a.get(b'target')
                    self.find_node_r(target, id, t, addr)
                    # TODO: 把主动 find_node、get_peers 的节点也加入 bucket
                elif q == b'get_peers':
                    info_hash = a.get(b'info_hash')
                    self.get_peers_r(info_hash, id, t, addr)
                elif q == b'announce_peer':
                    implied_port = a.get(b'implied_port')
                    info_hash = a.get(b'info_hash')
                    port = a.get(b'port')
                    token = a.get(b'token')
                    self.announce_peer_r(implied_port, info_hash, port, token, id, t, addr)
                elif q == b'vote': # ignore UT's vote
                    pass
                else:
                    raise self.DHTProtocolError(f'unknown q={repr(q)[:16]}')
            elif y == b'e':
                e = obj.get(b'e')
                if not isinstance(e, list) or not isinstance(e[0], int) or not isinstance(e[1], bytes):
                    raise self.DHTProtocolError('malformed y=e')
            else:
                raise self.DHTProtocolError(f'unknown y={repr(y)[:16]}')
        except self.DHTProtocolError as e:
            logging.debug(f'{e!r} from {addr[0]}:{addr[1]}, v={repr(v)[:16]}')
            if y == b'q' and isinstance(t, bytes):
                self.any_e([203, b'malformed packet'], t, addr)

    def error_received(self, exc):
        logging.debug(repr(exc))

    async def ticking(self):
        await asyncio.sleep(30)
        asyncio.ensure_future(self.ticking())
        for swarm in self.swarms:
            swarm.clean_bad_nodes(75)
            for bucket in swarm.buckets:
                for node in bucket:
                    if swarm.is_node:
                        self.find_node_q(swarm, node['addr'])
                    else:
                        self.get_peers_q(swarm, node['addr'])

    def dht_send(self, obj, addr):
        obj.setdefault(b'v', b'OT\x00\x01')
        self.transport.sendto(bencoder.bencode(obj), addr)

    @staticmethod
    def secure_nodeid(nodeid, ip):
        r = nodeid[-1] & 0x07
        ip_bytes = socket.inet_aton(ip)
        ip_bytes = bytes((
            (ip_bytes[0] & 0x03) | (r << 5),
            ip_bytes[1] & 0x0f,
            ip_bytes[2] & 0x3f,
            ip_bytes[3],
        ))
        hash = struct.pack('>I', crc32c(ip_bytes))
        secure = bytes((hash[0], hash[1], hash[2] & 0xf8 | nodeid[2] & 0x07)) + nodeid[3:]
        return secure

    def handle_nodes(self, nodes):
        for swarm in self.swarms:
            for i in range(0, len(nodes), 26):
                nodeid = nodes[i:i + 20]
                ip = nodes[i + 20:i + 24]
                port = struct.unpack('!H', nodes[i + 24:i + 26])[0]
                if nodeid == self.secure_nodeid(nodeid, socket.inet_ntoa(ip)) and \
                        swarm.is_valuable(nodeid):
                    node_addr = (socket.inet_ntoa(ip), port)
                    if swarm.is_node:
                        if time.time() - swarm.last_find_node.get(node_addr, 0) > self.find_node_protect: # 60 秒内不对同一个地址重复 get_peers
                            self.find_node_q(swarm, node_addr)
                    else:
                        if time.time() - swarm.last_get_peers.get(node_addr, 0) > self.get_peers_protect:
                            self.get_peers_q(swarm, node_addr)

    def ping_r(self, id, t, addr):
        self.dht_send({
            b't': t,
            b'y': b'r',
            b'r': {
                b'id': self.nodeid,
            },
        }, addr)

    def find_node_q(self, swarm, addr):
        swarm.last_find_node[addr] = time.time()
        self.dht_send({
            b't': b'fn',
            b'y': b'q',
            b'q': b'find_node',
            b'a': {
                b'id': self.nodeid,
                b'target': swarm.id,
            },
        }, addr)

    def find_node_t(self, id, nodes, addr):
        if id != self.secure_nodeid(id, addr[0]):
            raise self.DHTProtocolError('nodeid is not secure')
        nodes = nodes or b''
        if not isinstance(nodes, bytes) or len(nodes) % 26 != 0:
            raise self.DHTProtocolError('malformed nodeid')
        for swarm in self.swarms:
            if swarm.is_node:
                swarm.update(id)  # TODO: which swarm?
                if swarm.is_valuable(id):
                    logging.debug(f'add node {addr[0]}:{addr[1]} to swarm: same_bits={swarm.same_bits(swarm.id, id)}')
                    swarm.add(id, addr)
        self.handle_nodes(nodes)

    def find_node_r(self, target, id, t, addr):
        if not isinstance(target, bytes) or len(target) != 20:
            raise self.DHTProtocolError('malformed target')
        nodes = self.service_swarm.nearest_nodes(target)
        nodes_bin = b''.join(node['id'] + socket.inet_aton(node['addr'][0]) + struct.pack('!H', node['addr'][1]) for node in nodes)
        self.dht_send({
            b't': t,
            b'y': b'r',
            b'r': {
                b'id': self.nodeid,
                b'nodes': nodes_bin,
            },
        }, addr)

    def get_peers_q(self, swarm, addr):
        swarm.last_get_peers[addr] = time.time()
        self.dht_send({
            b't': b'gp',
            b'y': b'q',
            b'q': b'get_peers',
            b'a': {
                b'id': self.nodeid,
                b'info_hash': swarm.id,
            },
        }, addr)

    def get_peers_t(self, id, nodes, values, token, addr):
        if id != self.secure_nodeid(id, addr[0]):
            raise self.DHTProtocolError('nodeid is not secure')
        nodes = nodes or b''
        values = values or []
        if not isinstance(nodes, bytes) or len(nodes) % 26 != 0:
            raise self.DHTProtocolError('malformed nodes')
        elif not isinstance(values, list) or any(not isinstance(v, bytes) or len(v) != 6 for v in values):
            raise self.DHTProtocolError('malformed values')
        elif not isinstance(token, bytes):
            raise self.DHTProtocolError('malformed token')
        self.handle_nodes(nodes)
        for v in values:
            ip = v[0:4]
            port = struct.unpack('!H', v[4:6])[0]
            if (ip, port) not in self.peers:
                self.peers[ip, port] = {'found': time.time()}
                logging.info(f'peer found {socket.inet_ntoa(ip)}:{port} from node {addr[0]}:{addr[1]}')
        for swarm in self.swarms:
            if not swarm.is_node:
                if swarm.is_valuable(id):
                    logging.debug(f'add node {addr[0]}:{addr[1]} to swarm: same_bits={swarm.same_bits(swarm.id, id)}')
                    swarm.add(id, addr)
                if time.time() - swarm.last_announce_peer.get(addr, 0) > self.announce_peer_protect:
                    self.announce_peer_q(swarm, token, addr)

    def get_peers_r(self, info_hash, id, t, addr):
        if not isinstance(info_hash, bytes) or len(info_hash) != 20:
            raise self.DHTProtocolError('malformed info_hash')
        nodes = self.service_swarm.nearest_nodes(info_hash)
        nodes_bin = b''.join(node['id'] + socket.inet_aton(node['addr'][0]) + struct.pack('!H', node['addr'][1]) for node in nodes)
        values = self.info.get(info_hash, dict()).values()
        values_bin = [socket.inet_aton(peer['addr'][0]) + struct.pack('!H', peer['addr'][1]) for peer in values]
        token = secrets.token_bytes(8)
        self.tokens.append({'token': token, 'issue': time.time(), 'addr': addr})
        res = {
            b't': t,
            b'y': b'r',
            b'r': {
                b'id': self.nodeid,
                b'token': token,
                b'nodes': nodes_bin,
            },
        }
        if values_bin:
            res[b'r'][b'values'] = values_bin
        self.dht_send(res, addr)

    def announce_peer_q(self, swarm, token, addr):
        swarm.last_announce_peer[addr] = time.time()
        self.dht_send({
            b't': b'an',
            b'y': b'q',
            b'q': b'announce_peer',
            b'a': {
                b'id': self.nodeid,
                b'info_hash': swarm.id,
                b'implied_port': 1,
                b'port': 1,
                b'token': token,
            },
        }, addr)

    def announce_peer_t(self, id, addr):
        for swarm in self.swarms:
            if not swarm.is_node:
                swarm.update(id) # TODO: which swarm?

    def announce_peer_r(self, implied_port, info_hash, port, token, id, t, addr):
        if not isinstance(info_hash, bytes) or len(info_hash) != 20:
            raise self.DHTProtocolError('malformed info_hash')
        if implied_port not in (None, 0, 1):
            raise self.DHTProtocolError('malformed implied_port')
        if implied_port:
            peer_port = addr[1]
        else:
            if isinstance(port, int) and 0 <= port < 65536:
                peer_port = port
            else:
                raise self.DHTProtocolError('malformed port')
        # token expires in 600 seconds
        now = time.time()
        while len(self.tokens) > 0 and now - self.tokens[0]['issue'] > 600:
            self.tokens.pop(0)
        for obj in self.tokens:
            if obj['token'] == token and obj['addr'][0] == addr[0]:
                logging.debug(f'received info_hash <{base64.b16encode(info_hash).decode().lower()[:7]}> from {addr[0]}:{addr[1]}')
                self.info.setdefault(info_hash, dict())
                self.info[info_hash][addr[0]] = {'addr': (addr[0], peer_port), 'updated': time.time()}
                self.dht_send({
                    b't': t,
                    b'y': b'r',
                    b'r': {
                        b'id': self.nodeid,
                    },
                }, addr)
                break
        else:
            self.any_e([203, 'bad token'], t, addr)

    def any_e(self, e, t, addr):
        self.dht_send({
            b't': t,
            b'y': b'e',
            b'e': e,
        }, addr)


async def main():
    loop = asyncio.get_event_loop()

    dht_task = loop.create_datagram_endpoint(
        lambda: DHT(),
        local_addr=('0.0.0.0', 0))
    transport, protocol = await dht_task
    try:
        while True:
            await asyncio.sleep(.1) # Detect KeyboardInterrupt at each tick
    finally:
        transport.close()

if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=logging.INFO,
    )

    parser = argparse.ArgumentParser()
    parser.add_argument('bootstrap', type=str, nargs='?', default='bootstrap.nodes')
    args = parser.parse_args()

    with open(args.bootstrap, 'r') as f:
        BOOTSTRAP_NODES = [(s.split(':')[0], int(s.split(':')[1])) for s in f.readlines()]

    asyncio.get_event_loop().run_until_complete(main())
