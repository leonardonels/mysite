from django.db import models
from django.contrib.auth.models import AbstractUser
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import pyotp, base64
from mysite.settings import SECRET_KEY

# Create your models here.

class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN="ADMIN", 'admin'
        USER="USER", 'user'
        VERIFIED="VERIFIED", 'verified'

    base_role=Role.ADMIN

    role=models.CharField(max_length=50,choices=Role.choices)
    otp = models.BooleanField(default=False)
    otp_secret_encrypted = models.BinaryField(blank=True)  # Campo per memorizzare il segreto crittografato
    otp_secret_nonce = models.BinaryField(blank=True)      # Campo per memorizzare il nonce
    otp_secret_tag = models.BinaryField(blank=True)        # Campo per memorizzare il tag di autenticazione

    def save(self, *args, **kwargs):
        if not self.pk:
            self.role=self.base_role
        return super().save(*args, **kwargs)
    
    def is_superuser_custom(self):
        return self.role == 'ADMIN'
    
    @property
    def is_admin(self):
        return self.is_superuser_custom()
    
    def add_otp(self):
        self.otp = True
    
    def remove_otp(self):
        self.otp = False

    def toggle_otp(self):
        if self.otp:
            self.remove_otp()
        else:
            self.add_otp()
        self.save()

    def set_secret(self):
        self.otp_secret=pyotp.random_base32()
        self.encrypt_otp_secret()
        self.save()

    def generate_encryption_key(self):
        secret_key = SECRET_KEY.encode('utf-8')
        hashed_key = SHA256.new(data=secret_key).digest()
        return hashed_key[:32]


    def encrypt_otp_secret(self):
        key = self.generate_encryption_key()
        cipher = AES.new(key, AES.MODE_EAX)  # Usa AES.MODE_EAX
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(self.otp_secret.encode('utf-8'))

        #self.otp_secret_encrypted = base64.b64encode(ciphertext)
        #self.otp_secret_nonce = base64.b64encode(nonce)
        #self.otp_secret_tag = base64.b64encode(tag)
        self.otp_secret_encrypted = bytes(ciphertext)
        self.otp_secret_nonce = bytes(nonce)
        self.otp_secret_tag = bytes(tag)

        print("------------------------encode------------------------")
        print("-------------------------key--------------------------")
        print(key)
        print(type(key))
        print("----------------------otp_secret----------------------")
        print(self.otp_secret)
        print(type(self.otp_secret))
        print("------------------------cipher------------------------")
        print(cipher)
        print(type(cipher))
        print("----------------------ciphertext----------------------")
        print(ciphertext)
        print(type(ciphertext))
        print("--------------------ciphertext.sql--------------------")
        print(self.otp_secret_encrypted)
        print(type(self.otp_secret_encrypted))
        print("------------------------nonce-------------------------")
        print(nonce)
        print(type(nonce))
        print("----------------------nonce.sql----------------------")
        print(self.otp_secret_nonce)
        print(type(self.otp_secret_nonce))
        print("-------------------------tag--------------------------")
        print(tag)
        print(type(tag))
        print("------------------------tag.sql-----------------------")
        print(self.otp_secret_tag)
        print(type(self.otp_secret_tag))
        print("------------------------------------------------------")

        self.save()

    def decrypt_otp_secret(self):

        print("------------------------encode------------------------")
        print("-------------------------key--------------------------")
        #print(key)
        #print(type(key))
        print("----------------------otp_secret----------------------")
        #print(self.otp_secret)
        #print(type(self.otp_secret))
        print("------------------------cipher------------------------")
        #print(cipher)
        #print(type(cipher))
        print("----------------------ciphertext----------------------")
        #print(ciphertext)
        #print(type(ciphertext))
        print("--------------------ciphertext.sql--------------------")
        print(self.otp_secret_encrypted)
        print(type(self.otp_secret_encrypted))
        print("------------------------nonce-------------------------")
        #print(nonce)
        #print(type(nonce))
        print("----------------------nonce.sql----------------------")
        print(self.otp_secret_nonce)
        print(type(self.otp_secret_nonce))
        print("-------------------------tag--------------------------")
        #print(tag)
        #print(type(tag))
        print("------------------------tag.sql-----------------------")
        print(self.otp_secret_tag)
        print(type(self.otp_secret_tag))
        print("------------------------------------------------------")

        return "UXZDQ4CXGGILFKRAF23ZGIJBB3NPW7IG"
        #ciphertext = base64.b64decode(self.otp_secret_encrypted)
        #nonce = base64.b64decode(self.otp_secret_nonce)
        #tag = base64.b64decode(self.otp_secret_tag)
        #ciphertext = self.otp_secret_encrypted.encode('utf-8')
        #nonce = self.otp_secret_nonce.encode('utf-8')
        #tag = self.otp_secret_tag.encode('utf-8')
        #cipher = AES.new(self.generate_encryption_key(), AES.MODE_EAX, nonce=nonce)
        #decrypted_otp_secret = cipher.decrypt_and_verify(ciphertext, tag)
        #return decrypted_otp_secret.decode('utf-8')
        
class NormalUser(User):

    base_role=User.Role.USER

    class Meta:
        proxy=True