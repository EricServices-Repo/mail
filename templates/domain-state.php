<?php
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$db = new PDO('mysql:unix_socket=/var/lib/mysql/mysql.sock;dbname=postfixadmin', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$q = $db->prepare('SELECT domain FROM domain WHERE domain=?');
$q->execute([$input['domain']]);
if (!$q->fetchColumn()) { throw new RuntimeException('Unknown domain'); }
$q = $db->prepare('UPDATE domain SET modified=IF(active=?,modified,NOW()), active=? WHERE domain=?');
$value = $input['enabled'] ? 1 : 0;
$q->execute([$value, $value, $input['domain']]);
