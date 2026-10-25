<?php
require_once __DIR__.'/mfa-core.php';
$s=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$db=new PDO('mysql:unix_socket=/var/lib/mysql/mysql.sock','root','',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$q=$db->prepare('SELECT username FROM postfixadmin.mailbox WHERE username=?');$q->execute([$s['username']]);
if (!$q->fetchColumn()) { throw new RuntimeException('Unknown mailbox'); }
if ($s['op']==='enroll') {
    $hashes=array_map(fn($x)=>hash('sha256',$x),$s['recovery']);
    $q=$db->prepare('REPLACE INTO roundcubemail.mail_mfa (username,seed,recovery) VALUES (?,?,?)');
    $q->execute([$s['username'],mail_seed_encrypt($s['seed'],mail_mfa_key()),json_encode($hashes)]);
} elseif ($s['op']==='device') {
    $hash=crypt($s['password'],'$6$rounds=100000$'.bin2hex(random_bytes(8)).'$');
    if (strlen($hash)<80) { throw new RuntimeException('Hashing failed'); }
    $q=$db->prepare('INSERT INTO postfixadmin.mail_device_credential VALUES (?,?,?,?,FROM_UNIXTIME(?),0)');
    $q->execute([$s['id'],$s['username'],$hash,$s['label'],$s['expires']]);
} elseif ($s['op']==='revoke') {
    $q=$db->prepare('UPDATE postfixadmin.mail_device_credential SET revoked=1 WHERE username=? AND id=?');$q->execute([$s['username'],$s['id']]);
} elseif ($s['op']==='suspend') {
    $db->beginTransaction();
    $q=$db->prepare('UPDATE postfixadmin.mailbox SET active=0,smtp_active=0 WHERE username=?');$q->execute([$s['username']]);
    $q=$db->prepare('UPDATE postfixadmin.mail_device_credential SET revoked=1 WHERE username=?');$q->execute([$s['username']]);$db->commit();
} else { throw new RuntimeException('Unknown operation'); }
