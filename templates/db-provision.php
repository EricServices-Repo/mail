<?php
// Root's Unix-socket authentication; no root password or SQL credentials in argv.
$s = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$db = new PDO('mysql:unix_socket=/var/lib/mysql/mysql.sock', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
foreach (['postfixadmin', 'roundcubemail'] as $name) {
    $db->exec("CREATE DATABASE IF NOT EXISTS `$name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
}
foreach (['mail_admin', 'mail_lookup', 'mail_auth', 'roundcube'] as $user) {
    // Identifiers are constants; values go through prepared statements.
    $q = $db->prepare("CREATE USER IF NOT EXISTS '$user'@'localhost' IDENTIFIED BY ?");
    $q->execute([$s[$user]]);
    $q = $db->prepare("ALTER USER '$user'@'localhost' IDENTIFIED BY ?");
    $q->execute([$s[$user]]);
    $db->exec("REVOKE ALL PRIVILEGES, GRANT OPTION FROM '$user'@'localhost'");
}
$db->exec("GRANT ALL ON postfixadmin.* TO 'mail_admin'@'localhost'");
$db->exec("GRANT ALL ON roundcubemail.* TO 'roundcube'@'localhost'");
$db->exec("DROP DATABASE IF EXISTS test");
foreach ($db->query("SELECT User, Host FROM mysql.user WHERE User = '' OR (User = 'root' AND Host NOT IN ('localhost','127.0.0.1','::1'))") as $row) {
    $db->exec('DROP USER ' . $db->quote($row['User']) . '@' . $db->quote($row['Host']));
}
