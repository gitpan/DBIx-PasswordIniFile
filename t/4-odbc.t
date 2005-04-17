#!perl

use Test::More tests => 2;

use File::Spec;
use DBIx::PasswordIniFile;

$ini_file = File::Spec->rel2abs( File::Spec->catfile('.','t','odbc.ini') );

SKIP:
{
    skip('ODBC probably not installed on not Win32 systems', 2) if $^O ne 'MSWin32';
    skip("$ini_file does not exist", 2) if ! -e $ini_file;

    # Test for new with driver = ODBC

    $conn = new DBIx::PasswordIniFile( -file => $ini_file );

    ok( ref($conn) eq 'DBIx::PasswordIniFile', 'new driver=ODBC');

    # Test for connect

    $dbh = $conn->connect();
    ok( ref($dbh) eq 'DBI::db', 'connect driver=ODBC');

    $conn->disconnect();

}
