from cryptography.fernet import Fernet

class Crypto_fernet:
  #getter and setter
  def get_key(self):
    return self.key
  def set_key(self, key):
    self.key = key

  def gen_key(self):
    self.set_key(Fernet.generate_key())

  #writing key to a file
  def fernet_write_key(self):
      with open("key.key", "wb") as key_file:
          key_file.write(self.get_key())

  # Function to load the key from file
  def fernet_read_key(self):
    return open("key.key", "rb").read()

  #returns message encrypt
  def fernet_encrypt(self, msg_plain):
    self.set_key(self.fernet_read_key())
    msg_encoded = msg_plain.encode()
    
    fern_a = Fernet(self.get_key())
    msg_encrypted = fern_a.encrypt(msg_encoded)

    return msg_encrypted
  
  #returns message decrpyted
  def fernet_decrpyt(self, msg_encrypt):
    self.set_key(self.fernet_read_key())
    fernet_b = Fernet(self.get_key())
    
    msg_decrypted = fernet_b.decrypt(msg_encrypt)
    
    return msg_decrypted

#-------------------------------------------------------
def main():
  fern = Crypto_fernet()
  fern.gen_key()
  fern.fernet_write_key()

main()