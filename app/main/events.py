from flask import session
from flask_socketio import emit, join_room, leave_room
import random
from Crypto.Cipher import AES
from .. import socketio


@socketio.on('joined', namespace='/chat')
def joined(message):
    """Sent by clients when they enter a room.
    A status message is broadcast to all people in the room."""
    room = session.get('room')
    join_room(room)
    emit('status', {'msg': session.get('name') + ' has entered the room.'}, room=room)

def aes_encrypt(key, data, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    encd = aes.encrypt(data)
    return encd

def aes_decrypt(key, data, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    decd = aes.decrypt(data)
    return decd

@socketio.on('text', namespace='/chat')
def text(message):
    key = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    iv = ''.join([chr(random.randint(0, 0xFF)) for i in range(16)])
    data = 'hello world 1234' # <- 16 bytes

    enc = aes_encrypt(key,data,iv)
    dec = aes_decrypt(key,enc,iv)

    print('data:',data)
    print('cipher:', enc)
    print('plain:',dec)
    """Sent by a client when the user entered a new message.
    The message is sent to all people in the room."""
    room = session.get('room')


    

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

