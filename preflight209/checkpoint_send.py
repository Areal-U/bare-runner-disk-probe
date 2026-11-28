"""Send only an existing encrypted checkpoint or a signed, bounded stop record."""
import math
import os
from pathlib import Path
import sys
import time

import checkpoint_packets as p
import outcome_relay

SLICE_SECONDS = 240
WATERMARK_SECONDS = 360
START_SECONDS = 120


def plan(spare):
    # capacity() already reserved the first maximum packet. Retain budget for
    # every small ACK, for the separate readback half of the rendezvous.
    unit = p.archive_bound(p.PACKET_BYTES)
    headroom = spare + unit - p.MAX_COUNT*p.archive_bound(0)
    group = min(p.MAX_COUNT,headroom//unit)
    p.REQUIRE(group>=1,'Insufficient room for even one immutable packet and acknowledgements')
    barriers = math.ceil(p.MAX_COUNT/group)
    return group, START_SECONDS+p.MAX_COUNT*SLICE_SECONDS+2*barriers*WATERMARK_SECONDS


def preflight():
    p.normal.context()
    p.REQUIRE(os.environ['GITHUB_JOB']=='compile-probe','Wrong checkpoint preflight job')
    import packet_space
    floor = packet_space.before_compile(p.b.CAP,p.MAX_SEALED,p.PACKET_BYTES)
    spare = p.capacity(p.archive_bound(p.PACKET_BYTES),p.MAX_SEALED,time.time()+100,lead=p.normal.JOB_MINUTES*60)
    group,seconds = plan(spare)
    p.b.output(fallback_seconds=seconds,compile_disk_floor=floor)
    print(f'R209_PACKET_BUDGET max_packets={p.MAX_COUNT} packets_per_meter_barrier={group} '
          f'fallback_seconds={seconds}',flush=True)


def create_piece(source,outcome,index,count,size):
    p.reset('packet')
    import packet_space
    packet_space.before_piece(size)
    folder = p.folder('packet')
    digest = p.hashlib.sha256()
    with (folder/'piece.bin').open('xb') as dest:
        remaining = size
        while remaining:
            block = source.read(min(p.MIB,remaining))
            p.REQUIRE(block, 'Source ciphertext ended during packet staging')
            digest.update(block)
            dest.write(block)
            remaining-=len(block)
    piece = dict(schema='r209-checkpoint-piece-v1',claim=p.b.env_int('R28_COLLECTION_CLAIM'),index=index,
                 count=count,offset=index*p.PACKET_BYTES,bytes=size,sha256=digest.hexdigest(),outcome=outcome,
                 meter_barrier=True)
    return piece


def await_release(piece,row,deadline):
    while True:
        live = p.exact(row['key'],deadline)
        p.REQUIRE(live is None or live==row,'Immutable packet identity changed')
        if live is None:
            if not piece['meter_barrier']:
                return
            # Publisher held this exact row through a confirmed positive aggregate.
            # A released index row alone is insufficient when usage lags deletion.
            rows,usage = p.snapshot(deadline)
            if row['id'] not in rows and p.accounted((rows,usage)):
                print(f'R209_PACKET_METER_LOW id={row["id"]} bytes={usage[0]} count={usage[1]}',flush=True)
                return
        time.sleep(min(30 if piece['meter_barrier'] else 10,p.until(deadline)))


def send():
    p.REQUIRE(os.environ['GITHUB_JOB']=='compile-probe' and p.normal.R209,'Wrong checkpoint sender')
    root = p.normal.ROOT
    descriptor = p.normal.info()
    # The peer clock may start later than this worker. Respect both physical jobs.
    cutoff = outcome_relay.deadline()
    record = p.read_json(root/'outcome.json',64*1024)
    whole = p.validate_outcome(record,root/'writer.pem')
    if whole:
        p.REQUIRE(regular_cipher(root/'checkpoint.cms',record) and record['owner_recovery']==descriptor['owner_recovery'],
                  'Original ciphertext or owner envelope changed')
    else:
        p.REQUIRE(not (root/'checkpoint.cms').exists(), 'Control record must not carry candidate bytes')
    count = max(1,math.ceil(whole/p.PACKET_BYTES))
    # Each actual selection is re-evaluated at the write; time reserved before
    # compilation must still suffice for the measured finite transfer.
    logical = whole or len(p.data(record))
    debt = 0
    with (root/'checkpoint.cms' if whole else Path(os.devnull)).open('rb') as source:
        for index in range(count):
            size = min(p.PACKET_BYTES,whole-index*p.PACKET_BYTES)
            started = time.time()
            next_size = min(p.PACKET_BYTES,max(0,whole-(index+1)*p.PACKET_BYTES))
            piece = create_piece(source,record,index,count,size)
            def bind(spare,previous):
                if previous is None:
                    piece['meter_barrier'] = (index==count-1 or spare <
                                               p.archive_bound(next_size)+p.MAX_COUNT*p.archive_bound(0))
                else:
                    # An existing signed ACK commits the original choice even if
                    # today's free headroom has changed. Only two encodings are valid.
                    matches = [v for v in (True,False) if p.sha(p.data(dict(piece,meter_barrier=v)))==previous]
                    p.REQUIRE(len(matches)==1,'Existing ACK is for different packet bytes or outcome')
                    piece['meter_barrier'] = matches[0]
                window = SLICE_SECONDS+(2*WATERMARK_SECONDS if piece['meter_barrier'] else 0)
                end = started+window
                p.REQUIRE(time.time()<end<=cutoff,'Insufficient remaining per-packet transfer and meter time')
                (p.folder('packet')/'piece.json').write_bytes(p.data(piece))
                p.signature(p.folder('packet'),'piece',root/'key.pem')
                return end
            row = p.save('packet',index,min(cutoff,started+SLICE_SECONDS+2*WATERMARK_SECONDS),logical,debt=debt,
                         prepare=bind)
            barrier = piece['meter_barrier']
            stop = min(cutoff,started+SLICE_SECONDS+(2*WATERMARK_SECONDS if barrier else 0))
            ack = p.wait_row(p.key(index,'receipt'),min(stop,time.time()+SLICE_SECONDS))
            p.restore('receipt',index,ack,stop)
            p.verify_receipt(piece,row)
            await_release(piece,row,stop)
            debt = 0 if barrier else debt+row['size_in_bytes']
            print(f'R209_PACKET_ACK index={index} count={count} cache={row["id"]} '
                  f'receipt_cache={ack["id"]} barrier={str(barrier).lower()}',flush=True)
        p.REQUIRE(not source.read(1),'Ciphertext grew after sealing')
    p.b.output(packets_sent='true')


def regular_cipher(path,record):
    return p.regular(path,p.MAX_SEALED)==record['sealed_bytes'] and p.b.digest(path)==record['sealed_sha']


if __name__=='__main__':
    os.umask(0o077)
    p.REQUIRE(sys.argv[1:] in (['send'],['preflight']),'Expected preflight or send')
    (send if sys.argv[1]=='send' else preflight)()
