import csv
from cryptography.fernet import Fernet
import hashlib
#keygen is run whe key. key has yet to be generated
import keygen
#Crypto Classes
class Crypto_fernet_limited:
  #getter and setter
  def get_key(self):
    return self.key
  def set_key(self, key):
    self.key = key

  # def gen_key(self):
  #   self.set_key(Fernet.generate_key())

  # #writing key to a file
  # def fernet_write_key(self):
  #     with open("key.key", "wb") as key_file:
  #         key_file.write(self.get_key())

  # Function to load the key from file
  def fernet_read_key(self):
    return open("key.key", "rb").read()

  #read and write any named file
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

class Crypto_sha1:
  def __init__(self, msg):
    self.msg = msg

  def get_msg(self):
    return self.msg
  def set_msg(self, msg):
    self.msg = msg

  def sha1_encrypt(self):
    msg_encoded = str.encode(self.get_msg())
    msg_hash_sha1 = hashlib.sha1(msg_encoded)
    converted = msg_hash_sha1.hexdigest()
    
    return converted

class Crypto_md5:
  def __init__(self, msg):
    self.msg = msg
  
  def get_msg(self):
    return self.msg
  def set_msg(self, msg):
    self.msg = msg
  
  def md5_encrypt(self):
    msg_encoded = str.encode(self.get_msg())
    msg_hash_md5 = hashlib.md5(msg_encoded)
    converted = msg_hash_md5.hexdigest()

    return converted

#User Classes
class User:
  def __init__(self, user, pw):
    self.user = user
    self.pw = pw

  def get_user(self):
    return self.user
  def set_user(self, user):
    self.user = user
  
  def get_pw(self):
    return self.pw
  def set_pw(self, pw):
    self.pw = pw
  
  def login_check(self, input_user, input_pw):
    if input_user == self.get_user() and input_pw == self.get_pw():
      return True
    return False
  
class User_db:
  user_list = []
  current_user = User("","")
  # def __init__(self, user_list):
  #   self.user_list = user_list
  def get_user_list(self):
    return self.user_list
  def set_user_list(self, user_list):
    self.user_list = user_list
  def get_current_user(self):
    return self.current_user
  def set_current_user(self, current_user):
    self.current_user = current_user

  def read_file_and_fill_list(self, file):
      #Opening file to be read    
      with open(file, 'r') as myFile:
        lines = csv.reader(myFile, delimiter=',')
        for line in lines:
          file_user = line[0]
          file_pw = line[1]
          file_user = User(file_user, file_pw)
          
          #setting Var to user list
          list_user = self.get_user_list()
          #adding new user from file to Var
          list_user.append(file_user)
          #setting user list to new_Var
          self.set_user_list(list_user)

  def user_login_check(self, un, pw):
    #using linear search to find user
    for elem in self.get_user_list():
      #print(elem.get_user())
      if elem.login_check(un,pw):
        self.set_current_user(elem)
        return True
    return False

  def create_and_add_user_to_file(self, user, file):
    list_users = self.get_user_list()
    list_users.append(user)
    self.set_user_list(list_users)

    user_name = user.get_user()
    user_pw = user.get_pw()
    
    with open(file, mode='a') as the_file:
      the_writer = csv.writer(the_file, delimiter=',')
      the_writer.writerow([user_name, user_pw])


#-------------------------------------------------------
def main():
  #Reading key file to get token used for encryption
  fern_lim = Crypto_fernet_limited()
  #print(fern_lim.fernet_encrypt("test"))
  # token_key = fern_lim.fernet_read_key()
  token_key = b'3GZ5JyJpKmPGoZ95_EHk2uGISAmk9hrKrszRvOdDmIM='
  fern_lim.set_key(token_key)
  
  encrypted_file_str = fern_lim.read_file("users.csv")
  encrypted_file_de = encrypted_file_str.decode()
  encrypted_file = encrypted_file_de.encode()
  print("type key:", type(token_key))
  print("type file:", type(encrypted_file))
  print("file: ",encrypted_file)

  decrypted_file = fern_lim.fernet_decrpyt(encrypted_file)
 
  print("type file2:", type(encrypted_file))

  fern_lim.write_file("users.csv", decrypted_file)

  #Creating and filling list of users
  user_list = User_db()
  user_list.read_file_and_fill_list("users.csv")
  #login1 = User("admin", "admin")

  print("iYou.org")
  print("1) Login\n2) Create Account")
  choice = input("User Choice: ")
  choice = int(choice)

  #Login Choice
  if choice == 1:
    print("\nLogin")

    user_input = input("Username: ")
    pw_input = input("Password: ")

    #user_encrypt = fern_lim.fernet_encrypt(user_input)
    #fern_msg_decrypt = fernet1.fernet_decrpyt(fern_msg_encrypt)
    sha1_1 = Crypto_sha1(pw_input)
    md5_1 = Crypto_md5(user_input)
    
    pw_hash = sha1_1.sha1_encrypt()
    username_hash = md5_1.md5_encrypt()

    print("User hash:", username_hash)
    print("PW Hash:", pw_hash)
  

    #if user_list.user_login_check(user_input, pw_input):
    if user_list.user_login_check(username_hash, pw_hash):
      print("Success")
    else:
      print("No")
  elif choice == 2:
    print("Create Account")
    create_user_name = input("Username: ")
    create_user_pw = input("Password: ")

    sha1_1 = Crypto_sha1(create_user_name)
    md5_1 = Crypto_md5(create_user_pw)
    
    pw_hash = sha1_1.sha1_encrypt()
    username_hash = md5_1.md5_encrypt()

    create_User = User(username_hash, pw_hash)
    user_list.create_and_add_user_to_file(create_User, "users.csv")

    print(create_user_name, "Account Created")
main()



#Login credentials in txt file for test purposes
# admin,admin
# cesar,1234
# bob,abcd
# jp101,1234


#vs hashed username and passwords
# 21232f297a57a5a743894a0e4a801fc3,d033e22ae348aeb5660fc2140aec35850c4da997
# 6f597c1ddab467f7bf5498aad1b41899,7110eda4d09e062aa5e4a390b0a572ac0d2c0220
# 9f9d51bc70ef21ca5c14f307980a29d8,81fe8bfe87576c3ecb22426f8e57847382917acf
# 0dcdd3013883bb2ce068398a9d72a576, 7110eda4d09e062aa5e4a390b0a572ac0d2c0220
