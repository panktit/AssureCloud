import os
import sys
import dropbox
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import Crypto.Cipher.AES as AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

# this is used to create a counter.
# We have padded data in bytes.
# So we want the counter also to be in bytes
global nonce
nonce = get_random_bytes(8)
global app_key
global app_secret

# Storing the file_name to read from local machine and 
# upload with the file with the same filename with encrypted contents on dropbox
global username
global file_name
global local_filePath

local_filePath = "../content/"
#Store the encrypted key on dropbox with the following filename
global key_file_name


def createDirStructure(path):
  # If the directory does not exists then create one.
  if not os.path.exists(path):
    os.makedirs(path)

# Location of the file downloaded on local machine
global download_file_path
download_file_path = "../downloads/local"
createDirStructure(download_file_path)
key_file_path = "../keys"
createDirStructure(key_file_path)


# pad function - converts the data into hexadecimal format in bytes
# content: Data inside the user defined file
# Also equal chunks of block_size are created.
def pad(content):
  return content + b"\0" * (AES.block_size - len(content) % AES.block_size)
 
# striping the padded data
def unpad(content):
  return content.rstrip(b'\0')

def authenticate():
  # TO DO : Enter your app key and App secret.
  app_key = 'x03ls4fvmfws3v5'
  app_secret = 'w7hn9l5b960f1k0'
  
  # Get your app key and secret from the Dropbox developer website
  flow = dropbox.DropboxOAuth2FlowNoRedirect(app_key, app_secret)

  # Have the user sign in and authorize this token
  authorize_url = flow.start()
  print '1. Go to: ' + authorize_url
  print '2. Click "Allow" (you might have to log in first)'
  print '3. Copy the authorization code'
  code = raw_input("\nEnter the authorization code here: ").strip()

  # This will fail if the user enters an invalid authorization code
  try:
    oauth_result = flow.finish(code)
  except Exception, e:
    print('Error: %s' % (e,))
    return

  dbx = dropbox.Dropbox(oauth_result.access_token)
  # access_token = flow.finish(code)
  # client = dropbox.Dropbox(access_token)
  return oauth_result.access_token, dbx

def readFile():
  #fileName = "working-draft.txt
  with open(local_filePath + file_name) as in_file:
    content =  in_file.readlines()
  
  stringContent = ''.join(content)

  # Always length should be 32 so no need of padding
  # Encrypt this key with public key and store it on the cloud   
  secretKey = SHA256.new(stringContent).digest()
  return stringContent, secretKey

def generate_RSA_Key_Pair(user):
  # RSA will be used to create pair of public key and pvt key.
  # Using that public key I will encrypt secret key to store on the cloud.
  # Now only my paired secret from RSA can decrypt the data.
  keys = RSA.generate(1024)
  f = open(key_file_path+'/'+user+'_pvt_rsa_key.pem','w')
  f.write(keys.exportKey('PEM'))
  f.close()

  f = open(key_file_path+'/'+user+'_public_rsa_key.pem','w')
  f.write(keys.publickey().exportKey('PEM'))
  f.close()	

def getEncryptedSecretKey(secretKey, name):
  f = open(key_file_path+'/'+name+'_public_rsa_key.pem','r')
  publickey = RSA.importKey(f.read())
  encryptedSecretKey = publickey.encrypt(secretKey, None)
  return encryptedSecretKey

def encrypt():
  stringContent, secretKey = readFile();
  paddedContent   = pad(stringContent)
  # Note that - In counter mode no iv, but they use nonce + counter check wiki diagram
  # nonce is 8 bytes , and counter of 64 bytes, and create 64 * 8 = 512 bytes 
  # 512 bytes is the block size of AES blocks
  ctr = Counter.new(64,nonce)
  aes = AES.new(secretKey, AES.MODE_CTR,counter=ctr)
  ciphertext = aes.encrypt(paddedContent)
  #print "Encypted Content = " + ciphertext
  
  # Here used iv to randomize the data to greater extend.
  iv = Random.new().read(AES.block_size);
  return  iv+ciphertext, secretKey

def decrypt(ciphertext, secretKey):
  if len(ciphertext) <= AES.block_size:
    raise Exception ("Invalid ciphertext")
  
  ciphertext = ciphertext[AES.block_size:]
  ctr = Counter.new(64,nonce)
  aes = AES.new(secretKey, AES.MODE_CTR , counter=ctr)
  original_data = aes.decrypt(ciphertext)
  
  return original_data

def upload_files(ciphertext, encryptedSecretKey, access_token, client,user):

  try:
    #deduplication part => overwrite = True
    response = client.files_upload(ciphertext, "/data/"+file_name, mode=dropbox.files.WriteMode('overwrite', None))
    stringEncryptedKey = " ".join(encryptedSecretKey)
    responseFromKey = client.files_upload(stringEncryptedKey, "/keys/" + user + "/"+ key_file_name, mode=dropbox.files.WriteMode('overwrite', None))
    print username+", your encrypted file has been successfully uploaded!\n"
  except Exception as e : 
    print username+" - Error occured while uploading the file- " 
    print e   
  #print 'uploaded: ', response
  return access_token

def download_file(access_token, user):
  client = dropbox.Dropbox(access_token)
  #folder_metadata = client.metadata('/')
  #print 'metadata: ', folder_metadata
  
  metadata, f1 = client.files_download("/keys/" + user + "/" + key_file_name)
  f2 = open(key_file_path+'/'+user+'_pvt_rsa_key.pem','r')
  pvtkey = RSA.importKey(f2.read())
  decrypted = pvtkey.decrypt(f1.content)
 
  metadata, f = client.files_download("/data/"+ file_name)
  out = open(download_file_path + "/" + file_name, 'wb')
  out.write(decrypt(f.content, decrypted))
  out.close()

def share_file(user):
  '''
  User gets his/her own encrypted key from dropbox
  decrypts the key
  '''
  client = dropbox.Dropbox(access_token)
  metadata, f1 = client.files_download("/keys/"+username+"/" + key_file_name)
  f2 = open(key_file_path+'/'+username+'_pvt_rsa_key.pem','r')
  pvtkey = RSA.importKey(f2.read())
  decryptedKey = pvtkey.decrypt(f1.content)

  '''
  Re-seal this decrypted key with users public key
  '''
  encryptedSecretKeyForSharing = getEncryptedSecretKey(decryptedKey, user)
  return encryptedSecretKeyForSharing


# START
print "\n\n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n"
print "AssureCloud : Secure data storage and privacy protection for Dropbox clients\n\n" 
print "* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n"

print "Can you please authenticate yourself? \n";
access_token, client = authenticate()
username = client.users_get_current_account().name.given_name
print "Authentication successful! \n "
print "Generating RSA key pair for "+username+"\n"
generate_RSA_Key_Pair(username)
print "Hello, "+username+"!"

while(1):
  print "\n What do you want to do next . . .\n 1. Upload a file\n 2. Download a file \n 3. Share the file with friend\n 4. Exit\n"
  featureChoice=int (input("Enter your choice here : "))
  
  if featureChoice == 1:
    print "\n \n UPLOAD FILE FEATURE \n"
    file_name = raw_input("Enter file name: ")
    key_file_name = "encryptedkey_"+file_name
    print "File encryption in progress . . . "
    ciphertext, secretKey = encrypt()
    print username+", your file is encrypted successfully!\n"
    print "Creating new encrypted secret key\n"
    encryptedSecretKey = getEncryptedSecretKey(secretKey, username)

    print "File upload in progress . . . "
    access_token = upload_files(ciphertext,encryptedSecretKey, access_token, client, username)
  
  elif featureChoice == 2:
    print "\n \n DOWNLOAD FILE FEATURE \n"
    # Location of the file downloaded on local machine
    download_file_path = "../downloads/local"
    createDirStructure(download_file_path)
    file_name = raw_input("Enter file name: ")
    key_file_name = "encryptedkey_"+file_name
    print "Downloading the file - " + file_name + " \n Download location - " + download_file_path
    # First download the encrypted key file
    # Read its contents
    # Decrypt that secret key using the pvtkey from rsa
    # Use the secret key from decryption process to decrypt content from the data file
    download_file(access_token, username);
    print "Download successfully complete!"

  elif featureChoice == 3:
    print "\n \n SHARE FILE FEATURE \n"
    file_name = raw_input("Enter file name: ")
    key_file_name = "encryptedkey_"+file_name
    person = raw_input("Enter the name of person to share file with: ")
    generate_RSA_Key_Pair(person)
    print "Hi, I am "+username+"!"
    print "I am re-sealing this key with "+person+"'s public key"
    encryptedSecretKeyForSharing = share_file(person)

    # Assume user is notified ciphertext and encryptedSecretKeyForSharing
    print "\n Let us assume: "+username+" notifies "+person+" with key and cipher text! \n"
    download_file_path = "../downloads/shared/"+person
    createDirStructure(download_file_path)

    print "Done! Let me share this cryptic file and key with "+person+"\n\n"
    access_token = upload_files(ciphertext, encryptedSecretKeyForSharing, access_token, client, person)

    print "Hi, I am "+person+"!"
    print "Oh I received something from "+username+"!";
    print " Downloading the file - " + file_name + " \n Download location - " + download_file_path
    download_file(access_token, person)
    print "Download successfully complete!  Lets check!"

  elif featureChoice == 4:
    print "Goodbye!"
    sys.exit()
  else:
    print "Incorrect entry! :("