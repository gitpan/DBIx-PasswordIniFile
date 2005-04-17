use ExtUtils::MakeMaker;
use File::Spec;
use Crypt::CBC;

sub encryptPassword
{
    my $pass = shift;
  
    my $cipher = Crypt::CBC->new( {'key'             => 'esta es la clave',

                                   'cipher'          => 'Blowfish_PP'       
                                   # Put here your preferred installed Crypt::Module
                                  });
    $cipher->start('Encript');
    my $ciphertext = $cipher->encrypt_hex($pass);
    $cipher->finish();
    
    return $ciphertext;
}

sub read_odbc_params
{
    my $params = {};

    print "==== Properties of an ODBC DSN ====\n\n";

    print "What's the name of a valid ODBC DSN?\n";
    my $dsn = getLine();
    die "DSN is mandatory\n" if ! $dsn;

    print "What is the username?\n";
    my $username  = getLine() || '';

    print "What is the password?\n";
    my $password  = &encryptPassword(getLine() || '');

    return { driver => 'ODBC', dsn => $dsn, username => $username, password => $password };
}

sub read_other_params
{
    my $params = {};

    print "==== Properties of a database connection (not an ODBC DSN) ====\n\n";

    print "What is the dbi driver? (AKA mysql)\n";
    my $driver = getLine();
    $params->{driver} = $driver;
    die "driver is mandatory\n" if ! $driver;

    print "What is the name of the batabase?\n";
    my $database  = getLine();
    $params->{database} = $database;
    die "database is mandatory\n" if ! $database;

    print "What is the hostname where the database is located?\n";
    my $host  = getLine();
    $params->{host} = $host if defined($host);

    print "What is the port number where the SGBD listens? (default is 3306 in mysql)\n";
    my $port  = getLine();
    $params->{port} = $port if defined($port);

    print "What is the username?\n";
    my $username  = getLine() || '';
    $params->{username} = $username; 

    print "What is the password?\n";
    my $password  = &encryptPassword(getLine() || '');
    $params->{password} = $password; 

    return $params;
}

sub getLine {
	my $data = <STDIN>;
	chomp($data);
	return $data;
}

sub create_ini
{
    my($ini, $fnc) = @_;

    my $content = "[connection]\n";
    my %params = %{ &$fnc };
    while( my($key, $value) = each %params ) 
    { 
        $content .= "$key=$value\n";
    }
    
    open(INI_FILE, ">$ini") || die $!;
    print INI_FILE $content;
    close INI_FILE;

    print << "[EOM]"; 
A file $ini with the content

$content
has been created.
If you don't agree with its content modify it by hand
before running 'make test'.

[EOM]
    
}

print << "[EOM]";
############################################################
# IMPORTANT:
# For properly test this module it's required that you answer
# some questions giving properties of a database connection.
# Make sure to take at hand such a database connection.
# Additionally, if your platform is Win32 you'll be asked 
# for an ODBC DSN. If you havn't one, create it previously
# to running this installation.
#
# Your answers will be used for generating file t/connect.ini
# and optionally t/odbc.ini .
#
# (Press any key to continue).
############################################################
[EOM]
getLine();

&create_ini(
            File::Spec->catfile('.','t','odbc.ini'),
            \&read_odbc_params

           ) if $^O eq 'MSWin32';

&create_ini(
            File::Spec->catfile('.','t','connect.ini'),
            \&read_other_params

           );


# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
    'NAME'	=> 'DBIx::PasswordIniFile',
    'VERSION_FROM' => 'PasswordIniFile.pm', # finds $VERSION
    'PM' => {
              'PasswordIniFile.pm' => '$(INST_LIBDIR)/PasswordIniFile.pm'
            },
    'EXE_FILES' => [ 'encpassw.pl' ]
);

