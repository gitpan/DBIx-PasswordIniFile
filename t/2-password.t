#!perl

use Test::Simple tests => 8;

use DBIx::PasswordIniFile;
use Config::IniFiles;
use File::Spec;

$cfg = new Config::IniFiles(
           -file => File::Spec->catfile('.','t','password.ini') );
$cfg->setval('connection','password','--------');
$cfg->RewriteConfig();
$cfg->ReadConfig();

$conn = new DBIx::PasswordIniFile(
            -file => File::Spec->catfile('.','t','password.ini') );

# Test for encryptPassword and decryptPassword

$pass = 'this is my password';
$encrypt_pass = $conn->encryptPassword($pass);
$decrypt_pass = $conn->decryptPassword($encrypt_pass);
ok($decrypt_pass eq $pass, 'encryptPassword_ and decryptPassword_ w/ passw lenght > 0');

$pass = '';
$encrypt_pass = $conn->encryptPassword($pass);
$decrypt_pass = $conn->decryptPassword($encrypt_pass);
ok($decrypt_pass eq $pass, 'encryptPassword_ and decryptPassword_ w/ passw lenght == 0');

# Test for changePassword

$pass = 'this is my password';
$encrypt_pass = $conn->changePassword($pass);

$cfg->ReadConfig(); # Required after a setval and before a val

ok($pass eq $conn->decryptPassword($encrypt_pass), 'changePassword encrypts ok');
ok($encrypt_pass eq $cfg->val('connection','password'), 'changePassword saves ok');
ok($pass eq $conn->decryptPassword($cfg->val('connection','password')),'changePassword w/ length > 0');

$cfg->setval('connection','password','--------');
$cfg->RewriteConfig();
$cfg->ReadConfig();

$pass = '';
$encrypt_pass = $conn->changePassword($pass,$cfg);

$cfg->ReadConfig(); # Required after a setval and before a val

ok($pass eq $conn->decryptPassword($encrypt_pass), 'changePassword encrypts ok w/ blank password');
ok($encrypt_pass eq $cfg->val('connection','password'), 'changePassword saves ok w/ blank passw');
ok($pass eq $conn->decryptPassword($cfg->val('connection','password')),'changePassword w/ length == 0');
