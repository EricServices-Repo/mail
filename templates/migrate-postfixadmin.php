<?php
chdir('/opt/eric-mail/apps/postfixadmin/public');
$result = require 'upgrade.php';
if ($result !== true) { fwrite(STDERR, "PostfixAdmin migration failed\n"); exit(1); }
