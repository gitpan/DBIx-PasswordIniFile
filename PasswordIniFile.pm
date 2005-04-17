package DBIx::PasswordIniFile;

require v5.8.6;

use strict;
use vars qw($VERSION $AUTOLOAD);

($VERSION) = ' $Revision: 1.1 $ ' =~ /\$Revision:\s+([^\s]+)/;

use DBI();
use Config::IniFiles;
use Crypt::CBC;       # Requires Blowfish_PP or another cipher.

my %connect_cache;

sub new
{
    my $class = shift;
    my %args = @_;

    # Check that -file => $ini_file is a file
    return undef if !exists($args{-file}) || ! -e $args{-file};

    my $config = new Config::IniFiles( -file => $args{-file} );

    # If specified -section => $section, check that it exists
    return undef if $args{-section} && ! $config->SectionExists($args{-section});

    my $section = $args{-section};
    #if( exists( $args{-section} ) && 
    if( ! $args{-section} )
    {
        # Search section and assign to $section
        my @sections = grep( /^(dsn|connect|connection|database|db|virtual user)$/i, 
                              $config->Sections() );
        return undef  if !@sections;

        $section = $sections[0];
    }

    return bless { 
                   config_  => $config, 
                   section_ => $section,
                   key_     => ( $args{-key} || 'esta es la clave' ),
                   cipher_  => ( $args{-cipher} || 'Blowfish_PP' ),
                   dbh_     => 'dbh_'

                 }, $class;
}

sub connect
{
    my($self,$options) = @_;

    my @params = @{$self->getConnectParams_()};
    $params[-1] = { %{$params[-1]}, %$options } if $options && @params == 4;
    $params[3]  = $options if $options && @params == 3;
    $self->{dbh_} = DBI->connect( @params );

    return $self->{dbh_};
}
 
sub connectCached
{

    my($self,$options) = @_;
 
    my @params = @{$self->getConnectParams_()};
    $params[-1] = { %{$params[-1]}, %$options } if $options && @params == 4;
    $params[3]  = $options if $options && @params == 3;
    $self->{dbh_} = DBI->connect( @params );

    $connect_cache{$self} = $self;

    return $self->{dbh_};
}

sub changePassword
{
    my $self = shift;
    my $pass = shift;

    my $encrypt_pass = $self->encryptPassword($pass);

    my $cfg = $self->{config_};
    $cfg->setval($self->{section_},'password',$encrypt_pass);
    $cfg->RewriteConfig();
    $cfg->ReadConfig();
            
    return $encrypt_pass;
}

sub getCachedConnection
{
    my $class = shift;
    my $arg = shift;
    
    return undef if !$arg;

    foreach (keys %connect_cache)
    {
        my $cfg = $connect_cache{$_}->{config_};        
        return $connect_cache{$_} if $cfg->GetFileName() eq $arg;
    }
}

sub getCache
{
    my $class = shift;
    return \%connect_cache;
}

sub dbh
{
    my $self = shift;
    return $self->{dbh_};
}

##############################################################################
# AUTOLOAD function
# Magically executes functions of DBI
##############################################################################

sub AUTOLOAD
{
    my $self = shift;
    my @args = @_;

    my $name = $AUTOLOAD;
    $name =~ s/.*://;

    # Suppose we are calling a DBI function.
    return $self->{dbh_}->$name(@args) if ref($self);
    return DBI->$name(@args) if ! ref($self);
}

sub DESTROY
{
    return;
}

##############################################################################
# PRIVATE FUNCTIONS 
##############################################################################

sub getConnectParams_
{
    my $self = shift;

    my( $config, $section) = ( $self->{config_},
                               $self->{section_} );
    
    my($dsn,$username,$password,$attributes);

    my($driver,$database,$host,$port);
    $driver   = $config->val($section,'driver');
    $database = $config->val($section,'database');
    $host     = $config->val($section,'host') || '';
    $port     = $config->val($section,'port') || '';
    $dsn      = $config->val($section,'dsn') || '';
 
    $dsn  = "DBI:ODBC:${dsn}" if uc($driver) eq 'ODBC';
    $dsn  = "DBI:${driver}:database=${database}" . 
                      ($host ? ";host=${host}" : '') .
                      ($port ? ";port=${port}" : '')  if uc($driver) ne 'ODBC';
  
    $username = $config->val($section,'username') || '';
    $password = $self->decryptPassword($config->val($section,'password'));
 
    # attributes are supposed live in a file section called "$section_attributes" 
    # (without double quotes). In this section, each parameter is an attribute
    # name.
    
    return [ $dsn, $username, $password ]
    if ! $config->SectionExists("${section}_attributes") ;

    $attributes = {};
    if( $config->SectionExists("${section}_attributes") )
    {
        foreach my $attr ( $config->Parameters("${section}_attributes") )
        {
            $attributes->{$attr} = $config->val("${section}_attributes",$attr);
        }
    }

    return [ $dsn, $username, $password, $attributes ];
}

sub encryptPassword
{
    my $self = shift;
    my $pass = shift;
  
    my $cipher = Crypt::CBC->new( {'key'             => $self->{key_},
                                   'cipher'          => $self->{cipher_}
                                  });
    $cipher->start('Encript');
    my $ciphertext = $cipher->encrypt_hex($pass);
    $cipher->finish();
    
    return $ciphertext;
}

sub decryptPassword
{
    my $self = shift;
    my $pass = shift;
  
    my $cipher = Crypt::CBC->new( {'key'             => $self->{key_},
                                   'cipher'          => $self->{cipher_}
                                  });
    $cipher->start('Decript');
    my $plaintext = $cipher->decrypt_hex($pass);
    $cipher->finish();
    
    return $plaintext;
}

1;

__END__

=head1 NAME

DBIx::PasswordIniFile - Create DBI connections with password and other params stored in C<.ini> files.

=head1 SYNOPSIS

    use DBIx::PasswordIniFile;
    $conn = DBIx::PasswordIniFile->new( 
              -file    => 'path/to/file.ini',
              -section => 'db_config_section',
              -key     => 'encrypt_decrypt_key',
              -cipher  => 'name_of_encryption_module'
    );

    $conn->connect( \%attributes ); # or
    $conn->connect(); 

    $conn->connectCached( \%attributes ); # or
    $conn->connectCached();

    $encrypted_passw = $conn->changePassword('new_password');

    $conn = DBIx::PasswordIniFile->getCachedConnection( 'path/to/file.ini' );

    $hash_ref = DBIx::PasswordIniFile->getCache();

    $dbh = $conn->dbh();

=head1 DESCRIPTION

Lets you create a DBI connection with parameters stored in a C<.ini>
style file. The password is stored encrypted.

This module is similar to C<DBIx::Password>. The differences are that
DBI connection parameters aren't stored as part of the module source
code (but in an external C<.ini> style file), and that this module lets
you only one virtual user (i.e. one connection) per C<.ini> file. 

Like <DBIx::Password>, this is a subclass of DBI, so you may call DBI
function objects using C<DBIx::PasswordIniFile> objects.

=head1 FUNCTIONS

B<Note:>

C<[> and C<]> around words in syntax of functions below mean B<optional>, and
B<not> array reference.

=head2 C<$conn = DBIx::PasswordIniFile-E<gt>new( -file=E<gt>'path/to/file.ini' [, ... ])>

Creates a C<DBIx::PasswordIniFile> object from DBI connection parameters
specified in C<path/to/file.ini> file.

Apart from C<-file>, other (optional) arguments are:

=over 4

=item C<-section =E<gt> 'db_config_section'>

If specified, C<db_config_section> is the section of the C<.ini> file where
DBI connection parameters live.
If not specified, assumes that DBI connection parameters are in a section
with one of these names:

    dsn
    connect
    connection
    database
    db
    virtual user

Also, if attributes have to be specified, specify them as properties
of another section with same name and C<_attributes> at the end.
For example, if your C<.ini> file has a C<connect> section, connection
attributes (if specified) are assumed to be in C<connection_attributes>
section. If has a C<virtual user> section, attributes are assumed to be
in C<virtual user_attributes>, and so on.

Note:

Connection attributes are those you specify as last argument of DBI C<connect>
method. See L<DBI> for more details.

Allowed properties as DBI connection parameters are:

    driver
    database
    host
    port
    username
    password
    dsn

If C<driver=ODBC> then C<dsn>, C<username> and C<password> are mandatory, and
all other parameters are ignored.
If C<driver> isn't ODBC, then all parameters except C<database>, C<username>
and C<password> are optional.

Properties/Values in C<..._attributes> section aren't predefined and are used
as key/value pairs for C<\%attr> argument when DBI C<connect> method is
called.

All propertie values are stored as plain text in C<.ini> file, except
C<password> value, that is stored encrypted using an encription
algorithm (default is Blowfish_PP).

Below is an example of C<.ini> file content:

    [db_config_section]
    driver=mysql
    database=suppliers
    host=www.freesql.org
    port=3306
    username=ecastilla
    password=52616e646f6d495621c18a03330fee46600ace348beeec28
  
    [db_config_section_attributes]
    PrintError=1
    RaiseError=0
    AutoCommit=1

This is an example owith ODBC:

    [db_config_section]
    driver=ODBC
    dsn=FreeSQL

Other sections and properties of the C<.ini> file are ignored, and do not
cause any undesired effect. This lets you use non dedicated C<.ini> files
for storing DBI connection parameters.

The specified C<.ini> file must be a compatible C<Config::IniFiles> config
file (with default syntax, see L<Config::IniFiles> for detailed syntax).
Briefly:

=over 4

=item *

Lines beginning with C<#> are comments and are ignored. Also, blank lines are
ignored. Use this for readability purposes.

=item *

A section name is a string (including whitespaces) between C<[> and C<]>.

=item *

Each section has one or more property/value pairs. Each property/value pair
is specified with the syntax

    property=value

One property/value pair per line.

=back

=item C<-key =E<gt> 'encrypt_decrypt_key'> and C<-cipher =E<gt> 'name_of_encryption_module'>

If specified, C<-key> and C<-cipher> are the encryption/decription key used for
storing/eading the password in C<.ini> file and the cipher algoritm (default is 
'Blowfish_PP'). Note that at least one encription algorithm have to be installed
(they live in C<Crypt::> spacename).

=back

Once a C<DBIx::PasswordIniFile> object is created, use it to call DBI object
methods. For example:

    use DBIx::PasswordIniFile;
    $conn = new DBIx::PasswordIniFile( -file => 'my.ini');
    $conn->connect();
    ...
    $conn->disconnect(); # DBI object method.

=head2 C<$conn-E<gt>connect( [\%attributes] )>

Calls C<DBI-E<gt>connect> with values stored in C<.ini> file specified in C<new>.
C<\%attributes> refers to last parameter of C<DBI-E<gt>connect>.

If specified, C<\%attributes> take precedence over any conflicting stored in
C<..._attributes> section of C<.ini> file.

=head2 C<$conn-E<gt>connectCached( [\%attributes] )>

Same as C<connect>, but caches a copy of C<$conn> object.

Cached objects may be retrieved with L<C<getCachedConnection>>.

=head2 C<$encrypted_passw = $conn-E<gt>changePassword('new_password')>

Replaces the encrypted password stored in C<.ini> file with the result of
encrypting C<new_password> password (so, C<new_password> is the new
password in clear form).

Returns the new encrypted password saved in C<.ini> file.

=head2 C<$conn = DBIx::PasswordIniFile-E<gt>getCachedConnection( 'path/to/file.ini' )>

Returns a valid C<DBIx::PasswordIniFile> object corresponding to the C<.ini>
file argument, if its C<connectCached> was launched. Or returns C<undef> if argument
doesn't correspond to a cached connection.

=head2 C<$cache = DBIx::PasswordIniFile-E<gt>getCache()>

Return a hash reference that is the cache. Keys are object references converted to
strings and values are valid C<DBIx::PasswordIniFile> objects.

=head2 C<$dbh = $conn-E<gt>dbh()>

Returns the DBI database handler object (a C<DBIx::PasswordIniFile> object
is a composition of a C<DBI> object among others).

=head1 SECURITY CONSIDERATIONS

In C<.ini> file, password is stored encrypted, and never in clear form. But note
that the mechanism is not completely secured because passwords are stored clear
in memory. A hack may do a memory dump and see the password.

Although with this limitation, I think the module is a good balance between security
and simplicity.

=head1 REQUISITES

Perl v5.8.6 or above has to be installed. If not, an error

   Free to wrong pool XXX not YYY during global destruction

is displayed, and Perl crashes.

An encription module has to be installed. Default is to use
C<Crypt::Blowfish_PP> for encription and decription. If not installed, 
specify your preferred (without C<Crypt::> prefix).

=head1 SEE ALSO

There is an utility called L<encryptpassw.pl> that takes a C<.ini> file
and replaces the C<password> param value with its encrypted form.
 
L<DBI>, L<Config::IniFiles>, L<DBIx::Password>.

=head1 COPYRIGHT

Copyright 2005-2008 Enrique Castilla.

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself. 

This program is distributed in the hope that it will be useful, but without any 
warranty; without even the implied warranty of merchantability or fitness for a 
particular purpose. 

=head1 AUTHOR

Enrique Castilla E<lt>L<mailto:ecastillacontreras@yahoo.es|ecastillacontreras@yahoo.es>E<gt>.


