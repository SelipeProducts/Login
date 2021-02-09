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

  def write_file(self, file, content):
    with open(file, "wb") as key_file:
        key_file.write(content)
  #can read any file based off parameter input
  def read_file(self, file):
    return open(file, "rb").read()

  #returns message encrypt
  def fernet_encrypt(self, msg_plain):
    self.set_key(self.fernet_read_key())
    print("msg type:", type(msg_plain))
    if(type(msg_plain) == str):
      msg_encoded = msg_plain.encode()
    else:
      msg_encoded = msg_plain
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
  orig_file = ""
  encrypt_file =""
  fern = Crypto_fernet()
  print("Do you want to generate and write key to key file?")
  choice1 = input("Y/N: ")
  if(choice1 == "Y" or choice1 == "y"):
    fern.gen_key()
    fern.fernet_write_key()
  print("Do you want to hash the users file?")
  choice2 = input("Y/N: ")
  if(choice2 == "Y" or choice2 == "y"):
    orig_file = fern.read_file("users.csv")
    #orig_file = orig_file_byte.decode("utf-8")
    #orig_file = str(orig_file, 'utf-8')
    encrypt_file = fern.fernet_encrypt(orig_file)
    fern.write_file("user_backup.csv", orig_file)
    fern.write_file("users.csv", encrypt_file)
  

    print("orig", orig_file)
    print("crypto", encrypt_file)



main()


#user.csv with 4 users
# 21232f297a57a5a743894a0e4a801fc3,d033e22ae348aeb5660fc2140aec35850c4da997
# 6f597c1ddab467f7bf5498aad1b41899,7110eda4d09e062aa5e4a390b0a572ac0d2c0220
# 9f9d51bc70ef21ca5c14f307980a29d8,81fe8bfe87576c3ecb22426f8e57847382917acf
# 81dc9bdb52d04dc20036dbd8313ed055,315f166c5aca63a157f7d41007675cb44a948b33



#keygen
#3GZ5JyJpKmPGoZ95_EHk2uGISAmk9hrKrszRvOdDmIM=

