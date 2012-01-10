#!/usr/bin/perl -w

use strict;
use warnings 'all';
use Test::More 'no_plan';
use Data::Dumper;
use File::Slurp;
use FindBin qw/ $Bin /;
use lib "$Bin/../../lib";

#use Carp 'confess';
#$SIG{__DIE__} = \&confess;

use_ok('AWS::S3');
use_ok('AWS::CloudFront');


my @needed_env_vars = qw/AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY 
                        AWS_PRIVATE_KEY_FILE AWS_KEY_PAIR_ID AWS_BUCKET_NAME
                        AWS_BUCKET_NAME/;
foreach my $var (@needed_env_vars) 
{
  unless ($ENV{$var})
  {
    warn "\$ENV{$var} must be defined to run these tests.";
    exit(0);
  }
}

my $s3 = AWS::S3->new(
  access_key_id     => $ENV{AWS_ACCESS_KEY_ID},
  secret_access_key => $ENV{AWS_SECRET_ACCESS_KEY},
);

my $cf = AWS::CloudFront->new(
  access_key_id     => $ENV{AWS_ACCESS_KEY_ID},
  secret_access_key => $ENV{AWS_SECRET_ACCESS_KEY},
);

ok my ($bucket) =  grep { $_->name eq $ENV{AWS_BUCKET_NAME} } $s3->buckets;

cleanup();

SIGN_STRING: {
  my $to_sign = "Encrypt Me please just work";
  ok my $result = AWS::S3::File::_rsa_sha1_sign_OLD( $to_sign, $ENV{AWS_PRIVATE_KEY_FILE} );

  my $private_key = read_file($ENV{AWS_PRIVATE_KEY_FILE});
  my $result2 = AWS::S3::File::_rsa_sha1_sign( $to_sign, $private_key );
  is $result2, $result, "Signed versions match";

  #warn "*** result: $result ****\n";
}


DOWNLOAD_VIA_SIGNED_URL: {
  my $text = "Here is some content! " x 3;
  ok $bucket->add_file(
    key => 'code/test.txt',
    contents  => sub { return \$text }
  ), 'add file with code contents worked';

  ok my $file = $bucket->file('code/test.txt'), "got file back from bucket via s3";
  my $bucket_name = $bucket->name;
  my ($distribution) = grep {
    $_->Origin->DNSName eq "$bucket_name.s3.amazonaws.com";
  } $cf->distributions;

  ok $distribution, "got the distribution";
  #warn "**** Identity ******: "
  #. $distribution->OriginAccessIdentity->S3CanonicalUserId . "\n"; 

  #warn Dumper($cf->origin_access_identities);
  #warn "######## dist->CallerRef: " . $distribution->CallerReference . " #######";
  my $private_key = read_file($ENV{AWS_PRIVATE_KEY_FILE});
  ok my $signed_url = $file->cloudfront_url(
    private_key => $private_key,
    keypair_id => $ENV{AWS_KEY_PAIR_ID},
    distribution => $distribution,
    expires => "3000",
  ), "got signed cf url";
  warn "signed_url: $signed_url\n";

  ok my $contents = $cf->ua->get($signed_url)->content, "got contents via cf";

  is $contents, $text, "file from cf has correct contents";
  is ${$file->contents}, $text, "file.contents is correct";

  #$file->delete;
}


sub cleanup
{
  warn "\nCleaning Up...\n";

  my $file = $bucket->file( "code/test.txt" );
  return unless $file;
  warn "\tdelete: ", $file->key, "\n";
  #eval { $file->delete };
} # end cleanup()
