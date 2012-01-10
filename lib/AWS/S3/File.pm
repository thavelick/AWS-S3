
package AWS::S3::File;

use VSO;
use Carp 'confess';
use JSON::XS;
use MIME::Base64;
use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;

has 'key' => (
  is        => 'ro',
  isa       => 'Str',
  required  => 1,
);

has 'bucket' => (
  is        => 'ro',
  isa       => 'AWS::S3::Bucket',
  required  => 1,
  weak_ref  => 0,
);

has 'size'  => (
  is        => 'ro',
  isa       => 'Int',
  required  => 0,
);

has 'etag'  => (
  is        => 'ro',
  isa       => 'Str',
  required  => 0,
);

has 'owner'  => (
  is        => 'ro',
  isa       => 'AWS::S3::Owner',
  required  => 0,
  weak_ref  => 1,
);

has 'storageclass'  => (
  is        => 'ro',
  isa       => 'Str',
  required  => 0,
);

has 'lastmodified'  => (
  is        => 'ro',
  isa       => 'Str',
  required  => 0,
);

has 'contenttype'  => (
  is        => 'rw',
  isa       => 'Str',
  required  => 0,
  default   => sub { 'binary/octet-stream' }
);

has 'is_encrypted'  => (
  is        => 'rw',
  isa       => 'Bool',
  required  => 1,
  lazy      => 1,
  default   => sub {
    my $s = shift;

    my $type = 'GetFileInfo';
    my $req = $s->bucket->s3->request($type,
      bucket  => $s->bucket->name,
      key     => $s->key,
    );
    
    return $req->request->response->header('x-amz-server-side-encryption') ? 1 : 0;
  },
);

subtype 'AWS::S3::FileContents' => as 'CodeRef';
coerce 'AWS::S3::FileContents' =>
  from  'ScalarRef',
  via   { my $val = $_; return sub { $val } };

has 'contents' => (
  is        => 'rw',
  isa       => 'AWS::S3::FileContents',
  required  => 0,
  lazy      => 1,
  coerce    => 1,
  default   => \&_get_contents,
);

after 'contents' => sub {
  my ($s, $new_value) = @_;
  return unless defined $new_value;
  
  $s->_set_contents( $new_value );
  $s->{contents} = undef;
};

sub BUILD
{
  my $s = shift;
  
  return unless $s->etag;
  (my $etag = $s->etag) =~ s{^"}{};
  $etag =~ s{"$}{};
  $s->{etag} = $etag;
}# end BUILD()

sub update
{
  my $s = shift;
  my %args = @_;
  my @args_ok = grep {
    /^content(?:s|type)$/
  } keys %args;
  if ( @args_ok ) {
    $s->{ $_ } = $args{ $_ } for @args_ok;
    $s->_set_contents();
  }
  return ;
}# end update()


sub _get_contents
{
  my $s = shift;
  
  my $type = 'GetFileContents';
  my $req = $s->bucket->s3->request($type,
    bucket  => $s->bucket->name,
    key     => $s->key,
  );
  
  return \$req->request->response->decoded_content;
}# end contents()


sub _set_contents
{
  my ($s, $ref) = @_;
  
  my $type = 'SetFileContents';
  my %args = ( );
  my $response = $s->bucket->s3->request( $type,
    bucket                  => $s->bucket->name,
    file                    => $s,
    contents                => $ref,
    content_type            => $s->contenttype,
    server_side_encryption  => $s->is_encrypted ? 'AES256' : undef,
  )->request();
  
  (my $etag = $response->response->header('etag')) =~ s{^"}{};
  $etag =~ s{"$}{};
  $s->{etag} = $etag;
  
  if( my $msg = $response->friendly_error() )
  {
    die $msg;
  }# end if()
}# end _set_contents()


sub delete
{
  my $s = shift;
  
  my $type = 'DeleteFile';
  my $req = $s->bucket->s3->request($type,
    bucket  => $s->bucket->name,
    key     => $s->key,
  );
  my $response = $req->request();
  
  if( my $msg = $response->friendly_error() )
  {
    die $msg;
  }# end if()
  
  return 1;
}# end delete()

sub cloudfront_url
{
  my ($s, %args) = @_;

  foreach my $arg (qw(private_key keypair_id distribution expires))
  {
    die "Required argument: $arg not provided" unless $args{$arg};
  }

  my $distribution = $args{distribution};
  my $domain = $distribution->DomainName;
  my $path = $s->key;
  my $resource = "http://$domain/$path";
  my $expires = $args{expires} + time();
  my $private_key = $args{private_key};
  my $keypair_id = $args{keypair_id};

  my $policy = JSON::XS->new->utf8->encode({
    Statement => [
      Resource  => $resource,
      Condition => {
        DateLessThan  => {
          'AWS:EpochTime' => $expires
        }
      }
    ]
  });
  my $encoded_policy    = _url_safe_base64_encode( $policy );
  my $signature         = _rsa_sha1_sign($policy, $private_key);
  die "Could not generate signature" unless $signature;

  my $encoded_signature = _url_safe_base64_encode($signature);
  my $generated_url     = _create_url($resource, $encoded_policy, $encoded_signature, $keypair_id, $expires);

  return $generated_url;
}

sub _create_url {
  my ($path, $policy, $signature, $key_pair_id, $expires) = @_;

  my $result;
  my $separator = $path =~ m/\?/ ? '&' : '?';
  $result = "$path$separator" . "Policy=$policy&Signature=$signature&Key-Pair-Id=$key_pair_id";
  $result =~ s/\n//g;

  return $result;
}# end _create_url()


# Encode a string with base 64 encoding and replace some invalid URL characters
sub _url_safe_base64_encode
{
  my ($value) = @_;

  my $result = encode_base64($value);
  $result =~ tr|+=/|-_~|;

  return $result;
}# end _url_safe_base64_encode()


# Sign a document with given private key file.
# The first argument is the document to sign
# The second argument is the name of the private key file
sub _rsa_sha1_sign_OLD
{
  use File::Temp 'tempfile';
  use IPC::Open2;

  my ($to_sign, $pvkFile) = @_;

  return _write_to_program("openssl sha1 -sign $pvkFile", $to_sign);
}# end _rsa_sha1_sign()

sub _rsa_sha1_sign
{
  my ($to_sign, $private_key_text) = @_;
  my $rsa_private = Crypt::OpenSSL::RSA->new_private_key($private_key_text);
  $rsa_private->use_pkcs1_padding();
  return $rsa_private->sign($to_sign);
}

# Helper function to write data to a program
sub _write_to_program
{
  my ($prog, $data) = @_;

  my ($ifh, $ofh);
  my $pid = open2($ifh, $ofh, $prog);
  print $ofh $data;
  close $ofh;

  # slurp entire contents of output into scalar
  local $/;
  my $output = scalar(<$ifh>);
  close $ifh;

  waitpid($pid, 0);

  return $output;
}# end _write_to_program()

1;# return true:



=pod

=head1 NAME

AWS::S3::File - A single file in Amazon S3

=head1 SYNOPSIS

  my $file = $bucket->file('foo/bar.txt');
  
  # contents is a scalarref:
  print @{ $file->contents };
  print $file->size;
  print $file->key;
  print $file->etag;
  print $file->lastmodified;
  
  print $file->owner->display_name;
  
  print $file->bucket->name;
  
  # Set the contents with a scalarref:
  my $new_contents = "This is the new contents of the file.";
  $file->contents( \$new_contents );
  
  # Set the contents with a coderef:
  $file->contents( sub {
    return \$new_contents;
  });
  
  # Alternative update
  $file->update( 
    contents => \'New contents', # optional
    contenttype => 'text/plain'  # optional
  );
  
  # Delete the file:
  $file->delete();

=head1 DESCRIPTION

AWS::S3::File provides a convenience wrapper for dealing with files stored in S3.

=head1 PUBLIC PROPERTIES

=head2 bucket

L<AWS::S3::Bucket> - read-only.

The L<AWS::S3::Bucket> that contains the file.

=head2 key

String - read-only.

The 'filename' (for all intents and purposes) of the file.

=head2 size

Integer - read-only.

The size in bytes of the file.

=head2 etag

String - read-only.

The Amazon S3 'ETag' header for the file.

=head2 owner

L<ASW::S3::Owner> - read-only.

The L<ASW::S3::Owner> that the file belongs to.

=head2 storageclass

String - read-only.

The type of storage used by the file.

=head2 lastmodified

String - read-only.

A date in this format:

  2009-10-28T22:32:00

=head2 contents

ScalarRef|CodeRef - read-write.

Returns a scalar-reference of the file's contents.

Accepts either a scalar-ref or a code-ref (which would return a scalar-ref).

Once given a new value, the file is instantly updated on Amazon S3.

  # GOOD: (uses scalarrefs)
  my $value = "A string";
  $file->contents( \$value );
  $file->contents( sub { return \$value } );
  
  # BAD: (not scalarrefs)
  $file->contents( $value );
  $file->contents( sub { return $value } );

=head1 PUBLIC METHODS

=head2 delete()

Deletes the file from Amazon S3.

=head2 update()

Update contents and/or contenttype of the file.

=head1 SEE ALSO

L<The Amazon S3 API Documentation|http://docs.amazonwebservices.com/AmazonS3/latest/API/>

L<AWS::S3>

L<AWS::S3::Bucket>

L<AWS::S3::FileIterator>

L<AWS::S3::Owner>

=head1 AUTHOR

John Drago <jdrago_999@yahoo.com>

=head1 LICENSE AND COPYRIGHT

This software is Free software and may be used and redistributed under the same
terms as any version of perl itself.

Copyright John Drago 2011 all rights reserved.

=cut


