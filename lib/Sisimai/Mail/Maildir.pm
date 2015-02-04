package Sisimai::Mail::Maildir;
use feature ':5.10';
use strict;
use warnings;
use Class::Accessor::Lite;
use IO::Dir;
use IO::File;

my $roaccessors = [
    'dir',      # (String) path to Maildir/
];
my $rwaccessors = [
    'path',     # (String) path to each file 
    'file',     # (String) file name of a mail in the Maildir/
    'inodes',   # (Ref->Array) i-node list of files in the Maildir/
    'handle',   # (IO::File) File handle
];
Class::Accessor::Lite->mk_accessors( @$rwaccessors );
Class::Accessor::Lite->mk_ro_accessors( @$roaccessors );

sub new {
    # @Description  Constructor of Sisimai::Mail::Maildir
    # @Param <str>  (String) Path to Maildir/
    # @Return       (Sisimai::Mail::Maildir) Object
    #               (undef) Undef if the argument is not a directory or does not exist
    my $class = shift;
    my $argvs = shift // return undef;
    my $param = { 'inodes' => [] };

    return undef unless -d $argvs;

    $param->{'dir'}    = $argvs;
    $param->{'file'}   = undef;
    $param->{'path'}   = undef;
    $param->{'inodes'} = [];
    $param->{'handle'} = IO::Dir->new( $argvs );

    return bless( $param, __PACKAGE__ );
}

sub read {
    # @Description  Maildir reader, works as a iterator.
    # @Param
    # @Return       (String) Contents of file in Maildir/
    my $self = shift;

    return undef unless defined $self->{'dir'};
    return undef unless -d $self->{'dir'};

    my $seekhandle = $self->{'handle'};
    my $filehandle = undef;
    my $readbuffer = '';
    my $emailindir = '';
    my $emailinode = undef;

    eval {
        $seekhandle = IO::Dir->new( $self->{'dir'} ) unless $seekhandle;

        while( my $r = $seekhandle->read ) {
            # Read each file in the directory
            next if( $r eq '.' || $r eq '..' );

            $emailindir =  sprintf( "%s/%s", $self->{'dir'}, $r );
            $emailindir =~ y{/}{}s;
            next unless -f $emailindir;
            next unless -s $emailindir;
            next unless -T $emailindir;
            next unless -r $emailindir;

            # Get inode number of the file
            $self->{'path'} = $emailindir;
            $emailinode = [ stat $emailindir ]->[1];
            next if grep { $emailinode == $_ } @{ $self->{'inodes'} };

            $filehandle = IO::File->new( $emailindir, 'r' );
            while( my $f = <$filehandle> ) {
                # Concatenate the contents of each file
                $readbuffer .= $f;
            }
            $filehandle->close;

            push @{ $self->{'inodes'} }, $emailinode;
            $self->{'file'} = $r;

            last;
        }
    };
    return $readbuffer;
}

1;
__END__
=encoding utf-8

=head1 NAME

Sisimai::Mail::Maildir - Mailbox reader

=head1 SYNOPSIS

    use Sisimai::Mail::Maildir;
    my $maildir = Sisimai::Mail::Maildir->new('/home/neko/Maildir/new');
    while( my $r = $maildir->read ) {
        print $r;   # print contents of the mail in the Maildir/
    }

=head1 DESCRIPTION

Sisimai::Mail::Maildir is a reader for getting contents of each email in the
Maildir/ directory.

=head1 CLASS METHODS

=head2 C<B<new( I<path to Maildir/> )>>

C<new()> is a constructor of Sisimai::Mail::Maildir

    my $maildir = Sisimai::Mail::Maildir->new('/home/neko/Maildir/new');

=head1 INSTANCE METHODS

=head2 C<B<dir()>>

C<dir()> returns the path to Maildir/

    print $maildir->dir;   # /home/neko/Maildir/new/

=head2 C<B<path()>>

C<path()> returns the path to each email in Maildir/

    print $maildir->path;   # /home/neko/Maildir/new/1.eml

=head2 C<B<file()>>

C<file()> returns current file name of the Maildir.

    print $maildir->file;

=head2 C<B<files()>>

C<inodes()> returns i-node list of each email in Maildir.

    print for @{ $maildir->inodes };

=head2 C<B<handle()>>

C<handle()> returns file handle object (IO::Dir) of the Maildir.

    $maildir->handle->close;

=head2 C<B<read()>>

C<read()> works as a iterator for reading each email in the Maildir.

    my $maildir = Sisimai::Mail->new('/home/neko/Maildir/new');
    while( my $r = $mailbox->read ) {
        print $r;   # print each email in /home/neko/Maildir/new
    }

=head1 AUTHOR

azumakuniyuki

=head1 COPYRIGHT

Copyright (C) 2014-2015 azumakuniyuki E<lt>perl.org@azumakuniyuki.orgE<gt>,
All Rights Reserved.

=head1 LICENSE

This software is distributed under The BSD 2-Clause License.

=cut
