#!perl

use strict;
use vars qw($VERSION);

($VERSION) = ' $Revision: 1.1 $ ' =~ /\$Revision:\s+([^\s]+)/;

use Getopt::Long;
use File::Spec;
use Crypt::CBC;
use Config::IniFiles;

# Command line Arguments.
my($ini_file, $section, $key, $cipher);
GetOptions(
             'inifile=s' => \$ini_file,
             'section=s' => \$section,
             'key:s'     => \$key,
             'cipher:s'  => \$cipher
           );

sub encryptPassword
{
    my $pass = shift;
    my $key = shift || 'esta es la clave';
    my $cipher = shift || 'Blowfish_PP';
    
    my $cipher = Crypt::CBC->new( {'key'             => $key,
                                   'cipher'          => $cipher
                                  });
    $cipher->start('Encript');
    my $ciphertext = $cipher->encrypt_hex($pass);
    $cipher->finish();
    
    return $ciphertext;
}

my $cfg = new Config::IniFiles( -file => File::Spec->canonpath( $ini_file ) ) || die $!;
my $decrypt_passw = $cfg->val($section, 'password');
my $encrypt_passw = &encryptPassword( $decrypt_passw, $section, $key, $cipher);
$cfg->setval($section,'password',$encrypt_passw);
$cfg->RewriteConfig();
$cfg->ReadConfig();

__END__

=head1 NAME

encpassw.pl - Encrypts password in C<.ini> files

=head1 DESCRIPTION

Reads the value of a property C<password> in a configuration file ('a la'
C<.ini> style), and rewrites the value with the result of its encryption.

Style C<.ini> configuration files are those with a syntax compatible with
C<Config::IniFiles>, and briefly this means:

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

See L<Config::IniFiles> for detailed information about syntax.

=head1 SYNTAX

    perl encpassw.pl --inifile=<ini_file> 
                     --section=<section_name_of_ini_file_with_password_param>
                     [--key=<encryption_decryption_key> ]
                     [--cipher=<encryption_decryption_algorithm> ]

=head1 ARGUMENTS

=over 4

=item inifile

Name or pathname of file whose password value have to be encrypted.
It doen't need to have C<.ini> in its name.

=item section

Section name in C<inifile> where the C<password> property is.

=item key

Encryption / Decryption key in clear form.
Use the same value with C<DBIx::PasswordIniFile>.

=item cipher

Name of an installed cipher algoritm.
Cipher algoritma live in namespace C<Crypt::>.

Default is C<Crypt::Blowfish_PP>. If not specified, it must be installed.

=back

=head1 COPYRIGHT

Copyright 2005-2008 Enrique Castilla.

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself. 

This program is distributed in the hope that it will be useful, but without any 
warranty; without even the implied warranty of merchantability or fitness for a 
particular purpose. 

=head1 AUTHOR

Enrique Castilla E<lt>L<mailto:ecastillacontreras@yahoo.es|ecastillacontreras@yahoo.es>E<gt>.
