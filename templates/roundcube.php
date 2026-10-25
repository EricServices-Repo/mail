<?php
// Values are read from a root-managed, pool-readable JSON file, never shell expanded.
$s = json_decode(file_get_contents('/etc/eric-mail/roundcube.json'), true, 512, JSON_THROW_ON_ERROR);
$config['db_dsnw'] = 'mysql://roundcube:' . rawurlencode($s['password']) . '@localhost/roundcubemail';
$config['imap_host'] = 'ssl://' . $s['hostname'] . ':993';
$config['smtp_host'] = 'tls://' . $s['hostname'] . ':587';
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$config['imap_conn_options'] = ['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]];
$config['smtp_conn_options'] = ['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]];
$config['des_key'] = $s['des_key'];
$config['temp_dir'] = '/var/lib/roundcube/temp';
$config['log_driver'] = 'syslog';
$config['enable_installer'] = false;
$config['session_lifetime'] = 30;
$config['ip_check'] = true;
$config['login_autocomplete'] = 0;
$config['plugins'] = [];
$config['product_name'] = 'Mail';
$config['smtp_log'] = false;
