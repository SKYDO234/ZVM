"""Bounded parsing of one-time enrollment keys; no SSH agent or key discovery."""
import base64
import io
import paramiko
from engines import EngineError


class SSHError(EngineError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _key_string(blob, offset):
    if offset + 4 > len(blob):
        raise ValueError
    length = int.from_bytes(blob[offset:offset + 4], 'big')
    offset += 4
    if length > len(blob) - offset:
        raise ValueError
    return blob[offset:offset + length], offset + length


def _openssh_key_class(material):
    """Bound untrusted bcrypt work *before* a library can start key decryption.

    OpenSSH stores a caller-chosen 32-bit KDF round count in the key header.
    Size limits alone don't bound that CPU work. Also select the declared key
    type once so an incorrect passphrase doesn't repeat expensive decryption.
    """
    try:
        body = material.split('-----BEGIN OPENSSH PRIVATE KEY-----', 1)[1].split('-----END OPENSSH PRIVATE KEY-----', 1)[0]
        raw = base64.b64decode(''.join(body.split()), validate=True)
        if raw[:15] != b'openssh-key-v1\x00':
            raise ValueError
        cipher, offset = _key_string(raw, 15)
        kdf, offset = _key_string(raw, offset)
        options, offset = _key_string(raw, offset)
        if kdf == b'bcrypt':
            salt, end = _key_string(options, 0)
            if not 1 <= len(salt) <= 64 or end + 4 != len(options):
                raise ValueError
            rounds = int.from_bytes(options[end:], 'big')
            if not 1 <= rounds <= 256:
                raise SSHError('key_cost_limit', 'This private key’s decryption work factor exceeds the WebSSH safety limit (256 bcrypt rounds). Use your native SSH client or a dedicated key with a bounded work factor.')
            if cipher not in (b'aes256-ctr', b'aes256-cbc'):
                raise ValueError
        elif kdf != b'none' or cipher != b'none':
            raise ValueError
        if raw[offset:offset + 4] != b'\x00\x00\x00\x01':
            raise ValueError
        public, private_offset = _key_string(raw, offset + 4)
        payload, _ = _key_string(raw, private_offset)
        if len(payload) > 8192:
            raise SSHError('key_cost_limit', 'The private key payload exceeds the 8 KiB validation-work limit. Use a native SSH client for larger keys.')
        kind, public_offset = _key_string(public, 0)
        if kind == b'ssh-ed25519':
            return paramiko.Ed25519Key
        if kind == b'ssh-rsa':
            exponent, public_offset = _key_string(public, public_offset)
            modulus, _ = _key_string(public, public_offset)
            if len(modulus) > 1025 or int.from_bytes(modulus, 'big').bit_length() > 8192 or len(exponent) > 8:
                raise SSHError('key_cost_limit', 'Guest SSH accepts RSA keys up to 8192 bits with a bounded public exponent. Use a native SSH client for larger keys.')
            return paramiko.RSAKey
        if kind in (b'ecdsa-sha2-nistp256', b'ecdsa-sha2-nistp384', b'ecdsa-sha2-nistp521'):
            return paramiko.ECDSAKey
        raise ValueError
    except (ValueError, IndexError, UnicodeError):
        raise SSHError('invalid_private_key', 'Malformed or unsupported OpenSSH private key. No key decryption was attempted.') from None


def private_key(credentials):
    material = credentials['private_key']
    classes = (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey)
    if '-----BEGIN OPENSSH PRIVATE KEY-----' in material:
        classes = (_openssh_key_class(material),)
    elif len(material.encode('utf-8')) > 8192:
        raise SSHError('key_cost_limit', 'PEM private keys are limited to 8 KiB to bound key-validation work. Use a standard OpenSSH key or your native SSH client.')
    for key_class in classes:
        try:
            key = key_class.from_private_key(io.StringIO(credentials['private_key']), password=credentials.get('passphrase') or None)
            if key.get_bits() > 8192:
                raise SSHError('key_cost_limit', 'Guest SSH supports private keys up to 8192 bits. Use your native client for larger keys.')
            return key
        except paramiko.PasswordRequiredException:
            raise SSHError('key_passphrase_required', 'This private key is encrypted. Enter its passphrase and retry.') from None
        except (paramiko.SSHException, ValueError, TypeError):
            continue
    raise SSHError('invalid_private_key', 'Cannot read this private key or passphrase. Use an OpenSSH Ed25519, ECDSA or RSA key, or a PEM RSA/ECDSA key.')


