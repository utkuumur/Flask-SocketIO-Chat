from flask import session
from flask_socketio import emit, join_room, leave_room
from flask_common.crypto import (
    AuthenticationError,
    EncryptionError,
    aes_decrypt,
    aes_encrypt,
    aes_generate_key,
)
from .. import socketio


@socketio.on('joined', namespace='/chat')
def joined(message):
    """Sent by clients when they enter a room.
    A status message is broadcast to all people in the room."""
    room = session.get('room')
    join_room(room)
    emit('status', {'msg': session.get('name') + ' has entered the room.'}, room=room)


@socketio.on('text', namespace='/chat')
def text(message):
    """Sent by a client when the user entered a new message.
    The message is sent to all people in the room."""
    room = session.get('room')
    #key = aes_generate_key()
    key = b'utkuumurutkuumurutkuumurutkuumurutkuumurutkuumurutkuumurutkuumur'
    print('len:',len(key))
    print('key:',key)
    enc_msg = aes_encrypt(key, b'test')
    emit('enc_msg', {'msg': enc_msg}, room=room)
    emit('message', {'msg': session.get('name') + ':' + message['msg']}, room=room)



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

