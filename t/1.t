# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

my $temp_dir = '/tmp/captcha_temp';
my $temp_datadir = "$temp_dir/data";
my $temp_outputdir = "$temp_dir/img";
# we set this, cause we have to override the soon to be system wide settings
my $temp_imagesdir = 'Captcha/images';

use Test; # (tests => 27);

plan tests => 27;

use Authen::Captcha;
ok(1); # If we made it this far, we are fine.
my $captcha = Authen::Captcha->new();
ok( defined $captcha, 1, 'new() did not return anything' );
ok( $captcha->isa('Authen::Captcha') );

# make temp directories
ok( (-e $temp_dir) || mkdir($temp_dir) ); # made temp dir
ok( (-e $temp_datadir) || mkdir($temp_datadir) ); # made temp data dir
ok( (-e $temp_outputdir) || mkdir($temp_outputdir) ); # made temp image dir

my $captcha2 = Authen::Captcha->new(
	debug    	=> 1,
	datafolder	=> $temp_datadir,
	outputfolder	=> $temp_outputdir,
	expire  	=> 301,
	width   	=> 26,
	height  	=> 36
	);
ok( defined $captcha2, 1, 'new() did not return anything' );
ok( $captcha2->isa('Authen::Captcha') );

$captcha->debug(1);
ok( $captcha->debug(), '1', "couldn't set debug to 1" );
ok( $captcha2->debug(), '1', "couldn't set debug to 1" );

$captcha->datafolder($temp_datadir);
ok( $captcha->datafolder(), $temp_datadir, "couldn't set data folder to $temp_datadir" );
ok( $captcha2->datafolder(), $temp_datadir, "couldn't set data folder to $temp_datadir" );

$captcha->outputfolder($temp_outputdir);
ok( $captcha->outputfolder(), $temp_outputdir, "couldn't set data folder to $temp_outputdir" );
ok( $captcha2->outputfolder(), $temp_outputdir, "couldn't set data folder to $temp_outputdir" );

$captcha->expire(301);
ok( $captcha->expire(), '301', "couldn't set expire to 301" );
ok( $captcha2->expire(), '301', "couldn't set expire to 301" );

$captcha->width(26);
ok( $captcha->width(), '26', "couldn't set width to 26" );
ok( $captcha2->width(), '26', "couldn't set width to 26" );

$captcha->height(36);
ok( $captcha->height(), '36', "couldn't set height to 36" );
ok( $captcha2->height(), '36', "couldn't set height to 36" );

# override the default imagesfolder, cause the default where this will
# be installed is not there yet.
$captcha->imagesfolder($temp_imagesdir);
ok( $captcha->imagesfolder(), $temp_imagesdir, "Couldn't override the imagesfolder to $temp_imagesdir");

my ($md5sum,$code) = $captcha->generateCode(5);
ok( sub { return 1 if (length($code) == 5) }, 1, "didn't set the number of captcha characters correctly" );

my $results = $captcha2->checkCode($code,$md5sum);
# check for different error states
ok( sub { return 1 if ($results != -3) }, 1, "Failed on checkCode: invalid code (code does not match crypt)" );
ok( sub { return 1 if ($results != -2) }, 1, "Failed on checkCode: invalid code (not in database)" );
ok( sub { return 1 if ($results != -1) }, 1, "Failed on checkCode: code expired" );
ok( sub { return 1 if ($results !=  0) }, 1, "Failed on checkCode: code not checked (file error)" );
ok( $results,  1, "Failed on checkCode, didn't return 1, but didn't return the other error codes either." );

