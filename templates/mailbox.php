<?php
$s = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$db = new PDO('mysql:unix_socket=/var/lib/mysql/mysql.sock;dbname=postfixadmin', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$db->beginTransaction();
if ($s['kind'] === 'admin') {
    $hash = password_hash($s['password'], PASSWORD_DEFAULT);
    $q = $db->prepare('INSERT INTO admin (username,password,superadmin,created,modified,active) VALUES (?,?,1,NOW(),NOW(),1)');
    $q->execute([$s['address'], $hash]);
} else {
    $q = $db->prepare('SELECT domain FROM domain WHERE domain=? AND active=1');
    $q->execute([$s['domain']]);
    if (!$q->fetchColumn()) { throw new RuntimeException('Domain must be provisioned first'); }
    // crypt generates the SHA512-CRYPT scheme consumed by Dovecot/PFA.
    $hash = crypt($s['password'], '$6$rounds=100000$' . bin2hex(random_bytes(8)) . '$');
    if (strlen($hash) < 80) { throw new RuntimeException('Password hashing failed'); }
    $q = $db->prepare('INSERT INTO mailbox (username,password,name,maildir,quota,local_part,domain,created,modified,active,smtp_active) VALUES (?,?,?,?,?,?,?,NOW(),NOW(),1,1)');
    $q->execute([$s['address'], $hash, $s['local'], $s['domain'].'/'.$s['local'].'/', $s['quota'], $s['local'], $s['domain']]);
    $q = $db->prepare('INSERT INTO alias (address,goto,domain,created,modified,active) VALUES (?,?,?,NOW(),NOW(),1)');
    $q->execute([$s['address'], $s['address'], $s['domain']]);
}
$db->commit();
