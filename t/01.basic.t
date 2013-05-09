#!perl
use Test::More;
use strict;
use warnings;

use HTTP::Request::Common;
use HTTP::Status ':constants';
use Plack::Builder;
use Plack::Test;
use Plack::Session::State::Cookie;

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

my $base_app = sub {
    my $req = Plack::Request->new(shift);
    my $name = $req->param('name') or die 'name not found';
    return  [ HTTP_OK, [ 'Content-Type' => 'text/plain' ], [ "Hello " . $name ] ]
};


my $mapped = builder {
    mount "/post" => $base_app;
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

# normal input
my %app;

$app{'Basic App'} = builder {
    use Log::Dispatch;
    my $logger = Log::Dispatch->new(
        outputs => [
            [
                'Screen',
                min_level => 'debug',
                stderr    => 1,
                newline   => 1
            ]
        ],
    );
    enable "LogDispatch", logger => $logger;
    enable 'XSRFBlock';
    $mapped;
};

# psgix.input.buffered
$app{'psgix.input.buffered'} = builder {
    enable sub {
        my $app = shift;
        sub {
            my $env = shift;
            my $req = Plack::Request->new($env);
            my $content = $req->content; # <<< force psgix.input.buffered true.
            $app->($env);
        };
    };
    enable 'XSRFBlock';
    $mapped;
};

for my $appname ('Basic App', 'psgix.input.buffered') {
    subtest $appname => sub {
        test_psgi app => $app{$appname}, client => sub {
            my $cb  = shift;
            my ($res, $h_cookie);

            $res = $cb->(POST "http://localhost/post", [name => 'Plack']);
            is (
                $res->code,
                HTTP_FORBIDDEN,
                sprintf(
                    'POSTing to %s with no token returns HTTP_FORBIDDEN(%d)',
                    $res->request->uri,
                    HTTP_FORBIDDEN
                )
            );
            $h_cookie = $res->header('Set-Cookie') || '';
            is($h_cookie, '', 'Not trying to Set-Cookie after failed POST');

            $res = $cb->(GET "/form/html");
            is (
                $res->code,
                HTTP_OK,
                sprintf(
                    'GET %s returns HTTP_OK(%d)',
                    $res->request->uri,
                    HTTP_OK
                )
            );

            $h_cookie = $res->header('Set-Cookie') || '';
            $h_cookie =~ /PSGI-XSRF-Token=([^; ]+)/;
            my $token_from_cookie = $1 || '';

            ok(
                $token_from_cookie,
                sprintf(
                    'PSGI-XSRF-Token cookie being set with a value [%s]',
                    $token_from_cookie,
                )
            );

            $res = $cb->(POST "http://localhost/post", [name => 'Plack']);
            is (
                $res->code,
                HTTP_FORBIDDEN,
                sprintf(
                    'POSTing to %s with no token returns HTTP_FORBIDDEN(%d)',
                    $res->request->uri,
                    HTTP_FORBIDDEN
                )
            );

            $h_cookie = $res->header('Set-Cookie') || '';
            is($h_cookie, '', 'No longer trying to Set-Cookie');
        };
    };
}







done_testing;
