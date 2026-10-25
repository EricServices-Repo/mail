<?php
$s = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$db = new PDO('mysql:unix_socket=/var/lib/mysql/mysql.sock', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
foreach (['mail_admin', 'mail_lookup', 'mail_auth', 'roundcube'] as $user) {
    if (!isset($s[$user]) || !preg_match('/^[a-f0-9]{64}$/D', $s[$user])) {
        throw new RuntimeException('Invalid credential');
    }
}
foreach (['mail_admin', 'mail_lookup', 'mail_auth', 'roundcube'] as $user) {
    $q = $db->prepare("ALTER USER '$user'@'localhost' IDENTIFIED BY ?");
    $q->execute([$s[$user]]);
}
