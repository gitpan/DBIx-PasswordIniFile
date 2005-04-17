#!perl

use Test::More tests => 5;

use File::Spec;
use DBIx::PasswordIniFile;

# Test for connect

$ini_file = File::Spec->rel2abs( File::Spec->catfile('.','t','connect.ini') );

SKIP:
{
    skip("$ini_file does not exist", 5) if ! -e $ini_file;

$conn = new DBIx::PasswordIniFile( -file => $ini_file );

$db = $conn->connect();
ok( ref($db) eq 'DBI::db', 'connect');

ok( ref($conn->dbh()) eq 'DBI::db', 'dbh');

$conn->disconnect();

$db = $conn->connectCached();
ok( ref($db) eq 'DBI::db', 'connectCached');
$conn->disconnect();

$conn1 = DBIx::PasswordIniFile->getCachedConnection( $ini_file );
ok( ref($conn1) eq 'DBIx::PasswordIniFile', 'getCachedConnection w/ argument');

$cache = DBIx::PasswordIniFile->getCache();
ok( ref($cache) eq 'HASH', 'getCache' );

}
