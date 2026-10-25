# EricServices-Mail-Server  
Installation Script to Install:  
**Dovecot** - MDA Service  
**Postfix** - MTA Service  
**PostfixAdmin** - Domain and User Management  
**RoundCube** - Email Web Client 
Let's Encrypt SSL Certificate

# Features   
Dovecot and Postfix SSL Required  
Postfix whitelist to manage unwanted connections  
Postfix client restrictions  
SQL Database for multi-domain user management  

# Dependencies  
- Rocky Linux, Redhat, Fedora, or CentOS
- DNS Configuration
  - mail.domain.com - used for Roundcube Webmail
  - imap.domain.com - used for Dovecot IMAP service
  - smtp.domain.com - used by Postfix SMTP service
  - admin.domain.com - used by PostfixAdmin for admin management
  - MX Records
  - DMARC/SPF Records


# Installation    
## Live (Read the Code first!)  
    bash <(curl -s https://raw.githubusercontent.com/EricServices-Repo/mail/main/install.sh)  
    
## Manual:  
    cd /opt  
    wget https://raw.githubusercontent.com/EricServices-Repo/mail/main/install.sh
    chmod +x install.sh
    ./install.sh


# Variables  
DOMAIN = The domain for the email server  
SQLPASSWORD = Define the root user password for mysql  
PFAPASSWORD = Define the postfixadmin user password for mysql  
PFASETUPPASSWORD = The PostfixAdmin web install setup password  
ESREPO = EricServic.es Rocky Linux Repository  
CERTBOT = Toggle to enable Certbot install  


# Post Installation    
admin.domain.com/setup.php - PostfixAdmin Web Installer  
mail.domain.com/installer - RoundCube Web Installer  


# Access
admin.domain.com - Admin Portal  
mail.domain.com - Email Web Portal  


# Debug Commands 
**debugmail** - Sets the logging level higher for Dovecot and Postfix logs in /var/log  
**undebugmail** - Sets the logging level back to original level  


# Customization    
Toggle EricServic.es Repository usage  
Toggle CertBot to load certificates  
Toggle CertBot to use Staging Server (no rate limit for development)  


# Support    
[Discord](https://discord.gg/8nKBgURRbW)

