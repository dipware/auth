import base64
import time

def timestamp_ms():
    return int(time.time() * 1000)

def get_shortened_bytestring(bytestrang):
    return base64.encodebytes(bytestrang)[:8].decode("utf-8")