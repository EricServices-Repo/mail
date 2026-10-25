<?php
$db = new PDO('mysql:unix_socket=/var/lib/mysql/mysql.sock', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
foreach (['domain', 'mailbox', 'alias', 'alias_domain'] as $table) {
    $db->exec("GRANT SELECT ON postfixadmin.`$table` TO 'mail_lookup'@'localhost'");
}
$db->exec("GRANT SELECT ON postfixadmin.mailbox TO 'mail_auth'@'localhost'");
$db->exec("GRANT SELECT ON postfixadmin.domain TO 'mail_auth'@'localhost'");
// Web admin runtime does not need DDL. Schema upgrades run separately under root.
$db->exec("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'mail_admin'@'localhost'");
$db->exec("GRANT SELECT, INSERT, UPDATE, DELETE ON postfixadmin.* TO 'mail_admin'@'localhost'");
$db->exec("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'roundcube'@'localhost'");
$db->exec("GRANT SELECT, INSERT, UPDATE, DELETE ON roundcubemail.* TO 'roundcube'@'localhost'");
