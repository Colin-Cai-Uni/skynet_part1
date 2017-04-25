import struct
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

    def send(self, data):
        if self.shared_hash:
            # Create an initialization vector for the AES
            iv = Random.new().read(AES.block_size)
            ### TODO: Verify that trunacting the shared hash doesn't compromise security
            self.cipher = AES.new(self.shared_hash[:32], AES.MODE_CFB, iv)
            encrypted_data = iv + self.cipher.encrypt(data)
            #Usw HMAC to ensure the authentication and intergrity
            #Use SHA256 as the hash function
            mac_data = hamc.new(self.shared_hash[:32], encrypted_data, hashlib.sha256).hexdigest()
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("MAC data: {}".format(repr(mac_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)
        # Encode the MAC data's length into an unsigned two byte int ('M')
        pkt_mac_len = struct.pack('M', len(mac_data))
        self.conn.sendall(pkt_mac_len)
        self.conn.sendall(mac_data)
        

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        encrypted_data = self.conn.recv(pkt_len)
        # Decode the MAC data's length from an unsigned two byte int ('M')
        pkt_mac_len_packed = self.conn.recv(struct.calcsize('M'))
        unpacked_mac_contents = struct.unpack('M', pkt_mac_len_packed)
        pkt_mac_len = unpacked_contents[0]
        mac_data = self.conn.recv(pkt_mac_len)
        if self.shared_hash:
            # Decrypts the message using the given initialization vector
            self.cipher = AES.new(self.shared_hash[:32], AES.MODE_CFB, encrypted_data[:16])
            data = self.cipher.decrypt(encrypted_data[16:])
            updated_mac_data = hamc.new(self.shared_hash[:32], encrypted_data, hashlib.sha256).hexdigest()
            if hamc.compare_digest(mac_data, updated_mac_data):
                if self.verbose:
                    print("Receiving packet of length {}".format(pkt_len))
                    print("Encrypted data: {}".format(repr(encrypted_data)))
                    print("MAC data: {}".format(repr(updated_mac_data)))
                    print("Original data: {}".format(data))
                else:
                    data = encrypted_data
            else:
                print("Auth error!")
        return data


    def close(self):
        self.conn.close()
