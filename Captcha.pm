package Authen::Captcha;

# $Source: /usr/local/cvs/Captcha/pm/Captcha.pm,v $ 
# $Revision: 1.11 $
# $Date: 2003/12/02 19:45:26 $
# $Author: jmiller $ 
# License: GNU General Public License Version 2 (see license.txt)

use 5.00503;
use strict;
use GD;
use Digest::MD5 qw(md5_hex);
use Carp;

require Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
@ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Authen::Captcha ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
%EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

@EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

@EXPORT = qw(
	
);

$VERSION = sprintf "%d.%03d", q$Revision: 1.11 $ =~ /(\d+)/g;


# Preloaded methods go here.

sub new
{
	my ($this) = shift;
	my $class = ref($this) || $this;
	my $self = {};
	bless( $self, $class );
		
	my %opts = @_;

	# default character source images
	my $src_images = (defined($opts{imagesfolder}) && (-d $opts{imagesfolder}))
	                 ? $opts{imagesfolder} : '----SRC_IMAGES----/images';
	$self->imagesfolder($src_images);

	my $debug = (defined($opts{debug}) && ($opts{debug} =~ /^\d+$/))
	            ? $opts{debug} : 0;
	$self->debug($debug);
	$self->datafolder($opts{datafolder}) if($opts{datafolder});
	$self->outputfolder($opts{outputfolder}) if($opts{outputfolder});
	my $expire = (defined($opts{expire}) && ($opts{expire} =~ /^\d+$/))
	             ? $opts{expire} : 300;
	$self->expire($expire);
	my $width = (defined($opts{width}) && ($opts{width} =~ /^\d+$/))
	             ? $opts{width} : 25;
	$self->width($width);
	my $height = (defined($opts{height}) && ($opts{height} =~ /^\d+$/))
	             ? $opts{height} : 35;
	$self->height($height);
	
	# create a random seed
	my $os = $^O;
	if ($os =~ /linux/i)
	{	# linux os
		srand (time ^ $$ ^ unpack "%L*", `ps axww | gzip`);
	}
	elsif ( ($os =~ /MSWin/i) || ($os =~ /mac/i) )
	{
		# windows/mac os...
		# allowing perl to use what it thinks is a "good" seed
	}
	else
	{
		# hope we're on unix
		srand (time ^ $$ ^unpack "%L*", `ps -ef | gzip`);
	}

	return $self;
}

sub debug
{
	ref(my $self = shift) or croak "instance variable needed";
	if (@_)
	{
		$self->{_debug} = $_[0];
		return $self->{_debug};
	} else {
		return $self->{_debug};
	}
}

sub expire 
{
	ref(my $self = shift) or croak "instance variable needed";
	if (@_)
	{
		$self->{_expire} = $_[0];
		return $self->{_expire};
	} else {
		return $self->{_expire};
	}
}

sub width 
{
	ref(my $self = shift) or croak "instance variable needed";
	if (@_)
	{
		$self->{_width} = $_[0];
		return $self->{_width};
	} else {
		return $self->{_width};
	}
}

sub height 
{
	ref(my $self = shift) or croak "instance variable needed";
	if (@_)
	{
		$self->{_height} = $_[0];
		return $self->{_height};
	} else {
		return $self->{_height};
	}
}

sub outputfolder
{
	
	ref(my $self = shift) or croak "instance variable needed";
	if (@_)  
	{   # it's a setter
		$self->{_outputfolder} = $_[0];
		return $self->{_outputfolder};
	} else {
		return $self->{_outputfolder};
	}
}

sub imagesfolder
{
   ref(my $self = shift) or croak "instance variable needed";
   if (@_)
   {   # it's a setter
       $self->{_imagesfolder} = $_[0];
       return $self->{_imagesfolder};
   } else {
       return $self->{_imagesfolder};
   }
}

sub datafolder
{
   ref(my $self = shift) or croak "instance variable needed";
   if (@_)
   {   # it's a setter
       $self->{_datafolder} = $_[0];
       return $self->{_datafolder};
   } else {
       return $self->{_datafolder};
   }
}


sub checkCode {
	ref(my $self = shift) or croak "instance variable needed";
	my ($code, $crypt) = @_;

	$code = lc($code);
	
	warn "$code  $crypt\n" if($self->debug() >= 2);

	my $currenttime = time;
	my $returnvalue = 0;
	my $databasefile = $self->datafolder() . "/codes.txt";

	# zeros (0) and ones (1) are not part of the code
	# they could be confused with (o) and (l), so we swap them in
	$code =~ tr/01/ol/;

	my $md5 = md5_hex($code);
	
	# pull in current database
	warn "Open File: $databasefile\n" if($self->debug() >= 2);
	open (DATA, "<$databasefile")  or die "Can't open File: $databasefile\n";
		flock DATA, 1;  # read lock
		my @data=<DATA>;
	close(DATA);
	warn "Close File: $databasefile\n" if($self->debug() >= 2);

	my $passed=0;
	# $newdata will hold the part of the database we want to keep and 
	# write back out
	my $newdata = "";
	my $found;
	foreach my $fileline (@data) 
	{
		$fileline =~ s/\n//;
		my ($datatime,$datacode) = split(/::/,$fileline);
		
		my $pngfile = $self->outputfolder() . "/" . $datacode . ".png";
		if ($datacode eq $crypt)
		{
			# the crypt was found in the database
			if (($currenttime - $datatime) > $self->expire())
			{ 
				 warn "Crypt Found But Expired\n" if($self->debug() >= 2);
				# the crypt was found but has expired
				$returnvalue = -1;
			}
			else 	
			{
				warn "Match Crypt in File Crypt: $crypt\n" if($self->debug() >= 2);
				$found = 1;
			}
			# remove the found crypt so it can't be used again
			warn "Unlink File: " . $pngfile . "\n" if($self->debug() >= 2);
			unlink($pngfile);
		}
		elsif (($currenttime - $datatime) > $self->expire()){
			# removed expired crypt
			warn "Removing Expired Crypt File: " . $pngfile ."\n" if($self->debug() >= 2);
			unlink($pngfile);
		}
		else
		{
			# crypt not found or expired, keep it
			$newdata .= $fileline."\n";
		}
	}

	if ($md5 eq $crypt){
		warn "Match: " . $md5 . " And " . $crypt . "\n" if($self->debug() >= 2);
		# solution was correct
		if ($found){
			# solution was correct and was found in database - passed
			$returnvalue = 1;
		}
		elsif (!$returnvalue)
		{
			# solution was not found in database
			$returnvalue = -2;
		}
	}
	else 
	{
		warn "No Match: " . $md5 . " And " . $crypt . "\n" if($self->debug() >= 2);
		# incorrect solution
		$returnvalue = -3;
	}

	# update database
	open(DATA,">$databasefile")  or die "Can't open File: $databasefile\n";
		flock DATA, 2; # write lock 
		print DATA $newdata;
	close(DATA);
	
	return $returnvalue;
}

sub generateCode {
	ref(my $self = shift) or croak "instance variable needed";
	my ($length) = @_;

	my $databasefile = $self->datafolder() . "/codes.txt";	
	my $im_width = $self->width();

	# set a variable with the current time
	my $currenttime = time;

	# create a new image and color
	my $im = new GD::Image(($im_width * $length),$self->height());
	my $black = $im->colorAllocate(0,0,0);
	
	# generate a new code
	my $code = "";
	for(my $i=0; $i < $length; $i++){ 
		my $char;
		my $list = int(rand 4) +1;
		if ($list == 1)
		{ # choose a number 1/4 of the time
			$char = int(rand 7)+50;
		}
		else { # choose a letter 3/4 of the time
			$char = int(rand 25)+97;
		}
		$char = chr($char);
		$code .= $char;
	}
	my $md5 = md5_hex($code);
	
	# copy the character images into the code graphic
	for(my $i=0; $i < $length; $i++)
	{
		my $letter = substr($code,$i,1);
		my $letterpng = $self->imagesfolder() . "/" . $letter . ".png";
		my $source = new GD::Image($letterpng);
		$im->copy($source,($i*($self->width()),0,0,0,$self->width(),$self->height()));
		my $a = int(rand (int(($self->width())/14)))+0;
		my $b = int(rand (int(($self->height())/12)))+0;
		my $c = int(rand (int(($self->width())/3)))-(int(($self->width())/5));
		my $d = int(rand (int(($self->height())/3)))-(int(($self->height())/5));
		$im->copyResized($source,($i*($self->width()))+$a,$b,0,0,($self->width())+$c,($self->height())+$d,$self->width(),$self->height());
	}
	
	# distort the code graphic
	for(my $i=0; $i<($length*($self->width())*($self->height())/14+200); $i++)
	{
		my $a = (int(rand ($length*($self->width())))+0);
		my $b = (int(rand $self->height())+0);
		my $c = (int(rand ($length*($self->width())))+0);
		my $d = (int(rand $self->height())+0);
		my $index = $im->getPixel($a,$b);
		if ($i < (($length*($self->width())*($self->height())/14+200)/100)){
			$im->line($a,$b,$c,$d,$index);
		}
		elsif ($i < (($length*($self->width())*($self->height())/14+200)/2)){
			$im->setPixel($c,$d,$index);
		}
		else{
			$im->setPixel($c,$d,$black);
		}
	}
	
	# generate a background
	my $a = int(rand 5)+1;
	my $backgroundimg = $self->imagesfolder() . "/background" . $a . ".png";
	my $source = new GD::Image($backgroundimg);
	my ($backgroundwidth,$backgroundheight) = $source->getBounds();
	my $b = int(rand (int($backgroundwidth/13)))+0;
	my $c = int(rand (int($backgroundheight/7)))+0;
	my $d = int(rand (int($backgroundwidth/13)))+0;
	my $e = int(rand (int($backgroundheight/7)))+0;
	my $source2 = new GD::Image(($length*($self->width())),$self->height());
	$source2->copyResized($source,0,0,$b,$c,($length*($self->width())),$self->height(),$backgroundwidth-$b-$d,$backgroundheight-$c-$e);
	
	# merge the background onto the image
	$im->copyMerge($source2,0,0,0,0,($length*($self->width())),$self->height(),40);
	
	# add a border
	$im->rectangle(0,0,((($length)*($self->width()))-1),(($self->height())-1),$black);

	# create database file if it doesn't already exist
	if (! -e $databasefile)
	{
		open (DATA, ">>$databasefile") or die "Can't create File: $databasefile\n";
		close(DATA);
	}

	# clean expired codes and images
	open (DATA, "<$databasefile")  or die "Can't open File: $databasefile\n";
		flock DATA, 1;  # read lock
		my @data=<DATA>;
	close(DATA);
	
	my $newdata = "";
	foreach my $fileline (@data) 
	{
		$fileline =~ s/\n//;
		my ($datatime,$datacode) = split(/::/,$fileline);
		if (($currenttime - $datatime) > ($self->expire()) || $datacode  eq $md5)
		{
			my $outputdir = $self->outputfolder() . "/" . $datacode . ".png";
			unlink($outputdir);
		} else {
			$newdata .= $fileline."\n";
		}
	}
	
	# save the code to database
	warn "open File: $databasefile\n" if($self->debug() >= 2);
	open(DATA,">$databasefile")  or die "Can't open File: $databasefile\n";
		flock DATA, 2; # write lock
		warn "-->>" . $newdata . "\n" if($self->debug() >= 2);
		warn "-->>" . $currenttime . "::" . $md5."\n" if($self->debug() >= 2);
		print DATA $newdata;
		print DATA $currenttime."::".$md5."\n";
	close(DATA);
	warn "Close File: $databasefile\n" if($self->debug() >= 2);
	
	# save the image to file
	my $outputfile = $self->outputfolder() . "/" . $md5 . ".png";
	my $png_data = $im->png;

	warn "Open File: $outputfile\n" if($self->debug() >= 2);
	open (FILE,">$outputfile") or die "Can't open File: $outputfile \n";
		flock FILE, 2; # write lock
		binmode FILE;
		print FILE $png_data;
	close FILE;
	warn "Close File: $outputfile\n" if($self->debug() >= 2);
	
	# return crypt (md5)... or, if they want it, the code as well.
	return wantarray ? ($md5,$code) : $md5;
}

sub version
{
   return $VERSION;
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Authen::Captcha - Perl extension for creating captcha's to verify the human element in transactions.

=head1 DESCRIPTION

Authen::Captcha provides an object oriented interface to captcha file creations.  A Captcha is a program that can generate and grade tests that:
    - most humans can pass.
    - current computer programs can't pass

=head1 INSTALLATION

Download the zipped tar file from:

    http://search.cpan.org/search?dist=Authen-Captcha

Unzip the module as follows or use winzip:

    tar -zxvf Authen-Captcha-1.xxx.tar.gz

The module can be installed using the standard Perl procedure:

    perl Makefile.PL
    make
    make test
    make install    # you need to be root

Windows users without a working "make" can get nmake from:

    ftp://ftp.microsoft.com/Softlib/MSLFILES/nmake15.exe

=head1 SYNOPSIS

  use Authen::Captcha;

  # create a new object
  my $captcha = Authen::Captcha->new();

  # set the datafolder. contains flatfile db to maintain state
  $captcha->datafolder('/some/folder');

  # set directory to hold publicly accessable images
  $captcha->outputfolder('/some/http/folder');

  # optionally adjust the expriration time. Default 300 seconds.
  $captcha->expire(300);
  # optionally adjust the output character width. Default 25 pixels.
  $captcha->width(25);
  # optionally adjust the output character height. Default 35 pixels.
  $captcha->height(35);
  # optionally override the default character and background images
  # Default: ----SRC_IMAGES----/images
  $captcha->imagesfolder('/some/folder/holding/pngs');
  # optionally turn on debugging (0, 1, or 2. 0 is off/default)
  $captcha->debug(0);

  #   -OR-
  # you can set all these options from the new() constructor

  my $captcha = Authen::Captcha->new( {
    datafolder => '/some/folder',
    outputfolder => '/some/http/folder',
    expire => 300,
    width =>  25,
    height => 35,
    imagesfolder => '/some/folder/holding/pngs',
    debug => 0,
    } );

  # create a captcha. Image filename is "$md5sum.png"
  my $md5sum = $captcha->generateCode($number_of_characters);

  # if called in array context, it will also return a scalar variable
  # containing the actual randomly generated characters for this captcha
  my ($md5sum,$code) = $captcha->generateCode($number_of_characters);

  # check for a valid submitted captcha
  #   $code is the submitted letter combination guess from the user
  #   $md5sum is the submitted md5sum from the user (that we gave them)
  my $results = $captcha->checkCode($code,$md5sum);
  # $results will be one of:
  #          1 : Passed
  #          0 : Code not checked (file error)
  #         -1 : Failed: code expired
  #         -2 : Failed: invalid code (not in database)
  #         -3 : Failed: invalid code (code does not match crypt)
  ##############

=head1 ABSTRACT

Authen::Captcha provides an object oriented interface to captcha file creations.  A Captcha is a program that can generate and grade tests that:
    - most humans can pass.
    - current computer programs can't pass

The most common form is an image file containing distorted text, which humans are adept at reading, and computers (generally) do a poor job.
This module currently implements that method. We plan to add other methods,
such as distorted sound files, and plain text riddles.

=head2 EXPORT

None by default.

=head2 REQUIRES

    GD          (see http://search.cpan.org/~lds/GD-2.11/)
    Digest::MD5 (standard perl module)
    Carp        (standard perl module)

In most common situations, you'll also want to have:

 A web server (untested on windows, but it should work)
 cgi-bin or mod-perl access
 Perl: Perl 5.00503 or later must be installed on the web server.
 GD.pm 2.01 or later (with PNG support)

=head1 METHODS

=over

=item C<$captcha = Authen::Captcha-E<gt>new;>

This creates a new Captcha object.
Optionally, you can pass in a hash referance with configuration information.
See the method descriptions for more detail on what they mean.
  {
    datafolder => '/some/folder', # required
    outputfolder => '/some/http/folder', # required
    expire => 300, # optional. default 300
    width =>  25, # optional. default 25
    height => 35, # optional. default 35
    imagesfolder => '/some/folder', # optional. default to lib dir
    debug => 0, # optional. default 0
  }

=item C<$captcha-E<gt>datafolder( '/some/folder' );>

Required. Sets the directory to hold the flatfile database that will be used to store the current non-expired valid captcha md5sum's.
Must be writable by the process running the script (usually the web server user, which is usually either "apache" or "http"), but should not be accessable to the end user.

=item C<$captcha-E<gt>outputfolder( '/some/folder' );>

Required. Sets the directory to hold the generated Captcha image files. This is usually a web accessable directory so that the user can view the images in here, but it doesn't have to be web accessable (you could be attaching the images to an e-mail for some verification, or some other Captcha implementation).
Must be writable by the process running the script (usually the web server user, which is usually either "apache" or "http").

=item C<$captcha-E<gt>imagesfolder( '/some/folder' );>

Optional, and may greatly affect the results... use with caution. Allows you to override the default character graphic png's and backgrounds with your own set of graphics. These are used in the generation of the final captcha image file. The defaults are held in:
    ----SRC_IMAGES----/images

=item C<$captcha-E<gt>expire( 300 );>

Optional. Sets the number of seconds this captcha will remain valid. This means that the created captcha's will not remain valid forever, just as long as you want them to be active. Set to an appropriate value for your application. Defaults to 300.

=item C<$captcha-E<gt>width( 25 );>

Optional. Number of pixels high for the character graphics. Defaults to 25.

=item C<$captcha-E<gt>height( 35 );>

Optional. Number of pixels wide for the character graphics. Defaults to 35.

=item C<$md5sum = $captcha-E<gt>generateCode( $number_of_characters );>

Creates a captcha. Image filename is "$md5sum.png"

It can also be called in array context to retrieve the string of characters used to generate the captcha (the string the user is expected to respond with). This is useful for debugging.
ex.
  C<($md5sum,$chars) = $captcha-E<gt>generateCode( $number_of_characters );>

=item C<$results = $captcha-E<gt>checkCode($code,$md5sum);>

check for a valid submitted captcha
$code is the submitted letter combination guess from the user
$md5sum is the submitted md5sum from the user (that we gave them)
$results will be one of:
    1 : Passed
    0 : Code not checked (file error)
   -1 : Failed: code expired
   -2 : Failed: invalid code (not in database)
   -3 : Failed: invalid code (code does not match crypt)

=item C<$captcha-E<gt>debug( [0|1|2] );>

Optional. 
Sets the debugging bit. 1 turns it on, 0 turns it off. 2 will print out verbose messages to STDERR.

=back

=head1 SEE ALSO

The Captcha project:
    http://www.captcha.net/

The origonal perl script this came from:
    http://www.firstproductions.com/cgi/

=head1 AUTHOR

Seth T. Jackson, E<lt>sjackson@purifieddata.netE<gt>

First Productions, Inc. created the cgi-script distributed under the GPL which was used as the basis for this module. Much work has gone into making this more robust, and suitable for other applications, but much of the origonal code remains.

=head1 COPYRIGHT AND LICENSE

Copyright 2003, First Productions, Inc. (FIRSTPRODUCTIONS HUMAN TEST 1.0)

Copyright 2003 by Seth Jackson

This library is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version. (see license.txt).

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

=cut
