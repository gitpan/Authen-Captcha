use 5.00503;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Authen::Captcha',
    'VERSION_FROM'	=> 'Captcha.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'Captcha.pm', # retrieve abstract from module
       AUTHOR     => 'Seth T. Jackson <sjackson@purifieddata.net>') : ()),
#    'PM_FILTER'	=> 'grep -v \\"^\\#\\"',
#     'PM_FILTER'	=> "perl -p -e 's|TESTDATA|\$INSTALLSITELIB\$FULLEXT|g'",
#    'PM_FILTER'	=> 'perl filter.pl $INSTALLSITELIB',

#    'PM_FILTER'	=> 'perl -pe "s!TESTDATA!$(INSTALLSITELIB)/$(FULLEXT)!g"',
#    'PM_FILTER'	=> 'perl -pe "s!TESTDATA!$(INST_LIB)/$(FULLEXT)!g"',
    'PM_FILTER'	=> 'perl -pe "s!----SRC_IMAGES----!$(INSTALLSITELIB)/$(FULLEXT)!g"',
);
