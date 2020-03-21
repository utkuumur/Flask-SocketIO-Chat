from flask import session
from flask_socketio import emit, join_room, leave_room
import random
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import HMAC, SHA256
import os
import base64
from .. import socketio

BLOCK_SIZE = 128 // 8


@socketio.on('joined', namespace='/chat')
def joined(message):
    """Sent by clients when they enter a room.
    A status message is broadcast to all people in the room."""
    room = session.get('room')
    join_room(room)
    emit('status', {'msg': session.get('name') + ' has entered the room.'}, room=room)


def pad(data):
    length = 16 - (len(data) % 16)
    return data + chr(length)*length

def unpad(data):
    return data[:-data[-1]]

def verify_hmac(cipher,mac, hmac_key):
    local_hash = HMAC.new(hmac_key, digestmod=SHA256)
    local_hash.update(cipher)
    local_digest = _hash.digest()

    return SHA256.new(mac).digest() == SHA256.new(local_digest).digest()


def aes_encrypt(key, data):
    IV = Random.new().read(BLOCK_SIZE)
    aes = AES.new(key, AES.MODE_CBC, IV,segment_size=128)
    return base64.b64encode(IV + aes.encrypt(pad(data))).decode()

def aes_decrypt(key, data):
    enc = base64.b64decode(data)
    IV = enc[:BLOCK_SIZE]
    aes = AES.new(key, AES.MODE_CBC, IV, segment_size=128)
    return unpad(aes.decrypt(enc[BLOCK_SIZE:])).decode()

def decrypt_verify(key, data, hmac_key):
    enc = base64.b64decode(data)
    IV = enc[:BLOCK_SIZE]
    hmac = enc[-32:]
    cipher = enc[16:-32]

    ver_hmac = verify_hmac((iv+cipher), hmac, hmac_key)

    if ver_hmac:
        aes = AES.new(key, AES.MODE_CBC, IV, segment_size=128)
        return unpad(aes.decrypt(cipher)).decode()


@socketio.on('text', namespace='/chat')
def text(message):
    """Sent by a client when the user entered a new message.
    The message is sent to all people in the room."""
    room = session.get('room')
    emit('message', {
                     'cipher': message['msg'],
                     'msg': session.get('name')
                    }, room=room)

    '''
    key = os.urandom(32)
    #key = b"1234567890123456"
    data = message['msg'] 
    enc = aes_encrypt(key,data)
    print(type(enc),enc)
    dec = aes_decrypt(key,enc)

    print('data:',data)
    print('cipher:', enc)
    print(data == dec)
    print(data,dec)
    print('key hex:',key.hex())
    
    emit('message', {'key': key.hex(),
                     'cipher': enc,
                     'msg': session.get('name')
                    }, room=room)
    #emit('message', {'msg': session.get('name') + ':' + message['msg']}, room=room)
    '''

    

# Encrypt + sign using provided IV.
# Note: You should normally use aes_encrypt().
def aes_encrypt_iv(key, data, iv):
    aes_key = b'utkuumurutkuumurutkuumurutkuumur'
    iv = b'0000'
    encryptor = Cipher(
        algorithms.AES(aes_key), modes.CTR(iv), backend=backend
    ).encryptor()
    cipher = encryptor.update(data) + encryptor.finalize()
    return cipher

@socketio.on('left', namespace='/chat')
def left(message):
    """Sent by clients when they leave a room.
    A status message is broadcast to all people in the room."""
    room = session.get('room')
    leave_room(room)
    emit('status', {'msg': session.get('name') + ' has left the room.'}, room=room)

