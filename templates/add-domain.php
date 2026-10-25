<?php
// Root-only domain provisioning; no DNS, certificate or client-access mutation.
$input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$db = new PDO('mysql:unix_socket=/var/lib/mysql/mysql.sock;dbname=postfixadmin', 'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$q = $db->prepare('INSERT INTO domain (domain, description, aliases, mailboxes, maxquota, quota, transport, backupmx, created, modified, active) VALUES (?, ?, 100, 100, ?, 0, ?, 0, NOW(), NOW(), 1) ON DUPLICATE KEY UPDATE modified=IF(active=1,modified,NOW()), active=1');
$q->execute([$input['domain'], $input['domain'], $input['quota_mb'], 'virtual']);
