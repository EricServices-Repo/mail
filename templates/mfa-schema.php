<?php
$db=new PDO('mysql:unix_socket=/var/lib/mysql/mysql.sock','root','',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$db->exec("CREATE TABLE IF NOT EXISTS roundcubemail.mail_mfa (username VARCHAR(255) PRIMARY KEY,seed TEXT NOT NULL,recovery TEXT NOT NULL,last_counter BIGINT NOT NULL DEFAULT -1, failures INT NOT NULL DEFAULT 0,locked_until BIGINT NOT NULL DEFAULT 0) ENGINE=InnoDB");
$db->exec("CREATE OR REPLACE ALGORITHM=TEMPTABLE SQL SECURITY DEFINER VIEW roundcubemail.mail_account_status AS SELECT m.username,(m.active=1 AND d.active=1) AS active FROM postfixadmin.mailbox m JOIN postfixadmin.domain d ON m.domain=d.domain");
$db->exec("CREATE TABLE IF NOT EXISTS postfixadmin.mail_device_credential (id CHAR(24) PRIMARY KEY,username VARCHAR(255) NOT NULL,password VARCHAR(255) NOT NULL,label VARCHAR(64) NOT NULL,expires_at DATETIME NOT NULL,revoked TINYINT NOT NULL DEFAULT 0, INDEX(username)) ENGINE=InnoDB");
$db->exec("GRANT SELECT ON postfixadmin.mail_device_credential TO 'mail_auth'@'localhost'");
