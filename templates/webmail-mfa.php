<?php
class eric_mfa extends rcube_plugin {
    function init() {
        require_once '/opt/eric-mail/security/mfa-core.php';
        $this->add_hook('loginform_content',[$this,'form']);
        $this->add_hook('authenticate',[$this,'authenticate']);
        $this->add_hook('startup',[$this,'session_check']);
        $this->add_hook('login_after',[$this,'login_after']);
    }
    function form($args) {
        $args['inputs']['eric_otp']=['title'=>'Authenticator or recovery code','content'=>'<input name="_otp" type="password" autocomplete="one-time-code" required maxlength="64">'];return $args;
    }
    function authenticate($args) {
        $args['abort']=true;$args['error']='Authentication failed';
        // Never bypass Roundcube CSRF checks or allow device credentials through the web login.
        if (empty($args['valid']) || strpos($args['user'],'#')!==false) { return $args; }
        try {
            $code=(string)rcube_utils::get_input_string('_otp',rcube_utils::INPUT_POST);
            if (mail_mfa_verify(mail_mfa_db(),strtolower($args['user']),$code)) { $_SESSION['eric_mfa_pending']=time();$args['abort']=false;$args['error']=null; }
        } catch (Throwable $e) { /* generic failure: no secret or enrollment disclosure */ }
        return $args;
    }
    function login_after($args) { if (empty($_SESSION['eric_mfa_pending'])) { rcmail::get_instance()->kill_session();$args['_task']='login'; } else { $_SESSION['eric_mfa_verified']=time();unset($_SESSION['eric_mfa_pending']); } return $args; }
    function session_check($args) {
        if (empty($_SESSION['user_id'])) { return $args; }
        try { $valid=!empty($_SESSION['eric_mfa_verified']) && mail_mfa_active(mail_mfa_db(),(string)$_SESSION['username']); }
        catch (Throwable $e) { $valid=false; }
        if (!$valid) { rcmail::get_instance()->kill_session();$args['task']='login';$args['action']=''; }
        return $args;
    }
}
