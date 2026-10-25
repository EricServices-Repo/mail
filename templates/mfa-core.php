<?php
// RFC 6238 SHA-1 / 30-second TOTP. All persistent decisions use row locks.
function mail_base32_decode(string $text): string {
    if (!preg_match('/^[A-Z2-7]{16,128}$/D', $text)) { throw new RuntimeException('Invalid seed'); }
    $bits = ''; $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    foreach (str_split($text) as $c) { $bits .= str_pad(decbin(strpos($alphabet, $c)), 5, '0', STR_PAD_LEFT); }
    $out = ''; for ($i=0; $i+8<=strlen($bits); $i+=8) { $out .= chr(bindec(substr($bits,$i,8))); } return $out;
}
function mail_totp(string $seed, int $counter): string {
    $digest = hash_hmac('sha1', pack('N2', intdiv($counter,4294967296), $counter % 4294967296), mail_base32_decode($seed), true);
    $offset = ord($digest[19]) & 15;
    $value = unpack('N', substr($digest,$offset,4))[1] & 0x7fffffff;
    return str_pad((string)($value % 1000000),6,'0',STR_PAD_LEFT);
}
function mail_totp_counter(string $seed, string $code, int $now, int $last): ?int {
    if (!preg_match('/^[0-9]{6}$/D',$code)) { return null; }
    $counter = intdiv($now,30);
    for ($i=$counter+1; $i>=$counter-1; $i--) {
        if ($i>$last && hash_equals(mail_totp($seed,$i),$code)) { return $i; }
    }
    return null;
}
function mail_mfa_key(): string {
    $key = file_get_contents('/etc/eric-mail/mfa.key');
    if (strlen($key)!==SODIUM_CRYPTO_SECRETBOX_KEYBYTES) { throw new RuntimeException('MFA key unavailable'); } return $key;
}
function mail_seed_encrypt(string $seed, string $key): string {
    $nonce=random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return base64_encode($nonce.sodium_crypto_secretbox($seed,$nonce,$key));
}
function mail_seed_decrypt(string $value, string $key): string {
    $raw=base64_decode($value,true);
    if ($raw===false || strlen($raw)<40) { throw new RuntimeException('Invalid encrypted seed'); }
    $plain=sodium_crypto_secretbox_open(substr($raw,24),substr($raw,0,24),$key);
    if ($plain===false) { throw new RuntimeException('Seed authentication failed'); } return $plain;
}
function mail_mfa_db(): PDO {
    $s=json_decode(file_get_contents('/etc/eric-mail/roundcube.json'),true,512,JSON_THROW_ON_ERROR);
    return new PDO('mysql:unix_socket=/var/lib/mysql/mysql.sock;dbname=roundcubemail','roundcube',$s['password'],
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
}
function mail_mfa_active(PDO $db,string $user): bool {
    $q=$db->prepare('SELECT active FROM mail_account_status WHERE username=?'); $q->execute([$user]);
    return $q->fetchColumn()==1;
}
function mail_mfa_session_valid(PDO $db,string $user,string $version): bool {
    if (!mail_mfa_active($db,$user) || !preg_match('/^[a-f0-9]{64}$/D',$version)) { return false; }
    $q=$db->prepare('SELECT seed FROM mail_mfa WHERE username=?');$q->execute([$user]);$seed=$q->fetchColumn();
    return is_string($seed) && hash_equals(hash('sha256',$seed),$version);
}
function mail_mfa_verify(PDO $db,string $user,string $code,?string &$version=null): bool {
    $version=null; $db->beginTransaction();
    try {
        $q=$db->prepare('SELECT * FROM mail_mfa WHERE username=? FOR UPDATE');$q->execute([$user]);$row=$q->fetch(PDO::FETCH_ASSOC);
        $now=time();
        if (!$row || !mail_mfa_active($db,$user) || (int)$row['locked_until']>$now) { $db->rollBack(); return false; }
        $counter=mail_totp_counter(mail_seed_decrypt($row['seed'],mail_mfa_key()),$code,$now,(int)$row['last_counter']);
        $recovery=json_decode($row['recovery'],true,512,JSON_THROW_ON_ERROR);$used=null;
        foreach ($recovery as $i=>$hash) { if (hash_equals($hash,hash('sha256',$code))) { $used=$i; break; } }
        $ok=$counter!==null || $used!==null;
        if ($used!==null) { unset($recovery[$used]); }
        $fail=$ok?0:((int)$row['failures']+1);
        $q=$db->prepare('UPDATE mail_mfa SET last_counter=?, recovery=?, failures=?, locked_until=? WHERE username=?');
        $q->execute([$counter??$row['last_counter'],json_encode(array_values($recovery)),$fail,$fail>=5?$now+600:0,$user]);
        if ($ok) { $version=hash('sha256',$row['seed']); }
        $db->commit();return $ok;
    } catch (Throwable $e) { if ($db->inTransaction()) { $db->rollBack(); } throw $e; }
}
