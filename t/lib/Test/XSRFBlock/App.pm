package Test::XSRFBlock::App;
use strict;
use warnings;

use HTTP::Status qw(:constants);
use Plack::Builder;

my $form = <<FORM;
<html>
    <head><title>the form</title></head>
    <body>
        <form action="/post" method="post">
            <input type="text" name="name" />
            <input type="submit" />
        </form>
    </body>
</html>
FORM

my $form_outside = <<FORM;
<html>
    <head><title>the form</title></head>
    <body>
        <form action="http://example.com/post" method="post">
            <input type="text" name="name" />
            <input type="submit" />
        </form>
        <form action="http://example.com:80/post" method="post">
            <input type="text" name="text" />
            <input type="submit" />
        </form>
    </body>
</html>
FORM

my $form_localhost = <<FORM;
<html>
    <head><title>the form</title></head>
    <body>
        <form action="http://localhost/post" method="post">
            <input type="text" name="name" />
            <input type="submit" />
        </form>
    </body>
</html>
FORM

my $form_localhost_port = <<FORM;
<html>
    <head><title>the form</title></head>
    <body>
        <form action="http://localhost:80/post" method="post">
            <input type="text" name="name" />
            <input type="submit" />
        </form>
    </body>
</html>
FORM

sub base_app {
    my $base_app = sub {
        my $req = Plack::Request->new(shift);
        my $name = $req->param('name') or die 'name not found';
        return  [ HTTP_OK, [ 'Content-Type' => 'text/plain' ], [ "Hello " . $name ] ]
    };
}

sub mapped_app {
    my $mapped = builder {
        mount "/post" => base_app();
        mount "/form/html" => sub { [ HTTP_OK, [ 'Content-Type' => 'text/html' ], [ $form ] ] };
        mount "/form/xhtml" => sub { [ HTTP_OK, [ 'Content-Type' => 'application/xhtml+xml' ], [ $form ] ] };
        mount "/form/text" => sub { [ HTTP_OK, [ 'Content-Type' => 'text/plain' ], [ $form ] ] };
        mount "/form/html-charset" => sub { [ HTTP_OK, [ 'Content-Type' => 'text/html; charset=UTF-8' ], [ $form ] ] };
        mount "/form/xhtml-charset" => sub { [ HTTP_OK, [ 'Content-Type' => 'application/xhtml+xml; charset=UTF-8' ], [ $form ] ] };
        mount "/form/text-charset" => sub { [ HTTP_OK, [ 'Content-Type' => 'text/plain; charset=UTF-8' ], [ $form ] ] };

        mount "/form/html-outside" => sub { [ HTTP_OK, [ 'Content-Type' => 'text/html' ], [ $form_outside ] ] };
        mount "/form/html-localhost" => sub { [ HTTP_OK, [ 'Content-Type' => 'text/html' ], [ $form_localhost ] ] };
        mount "/form/html-localhost-port" => sub { [ HTTP_OK, [ 'Content-Type' => 'text/html' ], [ $form_localhost_port ] ] };
    };
}

1;
