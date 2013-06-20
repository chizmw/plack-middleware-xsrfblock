#!perl
use Test::More;
use strict;
use warnings;

use HTTP::Cookies;
use HTTP::Request::Common;
use HTTP::Status ':constants';
use LWP::UserAgent;
use Plack::Builder;
use Plack::Test;
use Plack::Session::State::Cookie;

use FindBin::libs;
use Test::XSRFBlock::App;

my $mapped = Test::XSRFBlock::App->mapped_app;

# normal input
my %app;

$app{'psgix.input.non-buffered'} = builder {
    if ($ENV{PLACK_DEBUG}) {
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
    }
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

for my $appname ('psgix.input.non-buffered', 'psgix.input.buffered') {
    subtest $appname => sub {
        my $ua = LWP::UserAgent->new;
        $ua->cookie_jar( HTTP::Cookies->new );

        test_psgi ua => $ua, app => $app{$appname}, client => sub {
            my $cb  = shift;
            my ($res, $h_cookie, $jar, $token);
            $jar = $ua->cookie_jar;

            # make a standard get request; we shouldn't trigger any xSRF
            # rejections but we *should* see the header trying to set the new
            # cookie
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

            set_cookie_ok($res);
            $token = cookie_in_jar_ok($res, $jar);

            my $expected_content=qq{<html>
    <head><title>the form</title></head>
    <body>
        <form action="/post" method="post"><input type="hidden" "name="xsrf_token" value="$token" />
            <input type="text" name="name" />
            <input type="submit" />
        </form>
    </body>
</html>
};
            is ($res->content, $expected_content, 'response content appears sane');
        };
    };
}

sub forbidden_ok {
    my $res = shift;
    is (
        $res->code,
        HTTP_FORBIDDEN,
        sprintf(
            '"POST %s" returns HTTP_FORBIDDEN(%d)',
            $res->request->uri,
            HTTP_FORBIDDEN
        )
    );
    return $res;
}

sub set_cookie_ok {
    my $res = shift;
    my $h_cookie = $res->header('Set-Cookie') || '';
    $h_cookie =~ /PSGI-XSRF-Token=([^; ]+)/;
    my $token_from_cookie = $1 || '';
    ok(
        $token_from_cookie,
        'cookie being set with a non-blank value'
    );
}

sub cookie_in_jar_ok {
    my $res = shift;
    my $jar = shift;
    my $msg = shift ||
        'cookie has a defined value when retrieved';

    $jar->extract_cookies($res);
    like(
        $jar->as_string,
        qr{PSGI-XSRF-Token},
        'PSGI-XSRF-Token found in cookie jar',
    );
    my $token = _cookie_value($jar, 'PSGI-XSRF-Token');
    ok(
        defined $token,
        $msg
    );

    return $token;
}

sub _cookie_value {
    my $jar = shift;
    my $cookie_name = shift || return;

    my $token;
    $jar->scan(
        sub{$token = $_[2] if $_[1] eq $cookie_name;}
    );
    return $token;
}


done_testing;
