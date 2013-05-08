package Plack::Middleware::XSRFBlock;
use strict;
use warnings;
use parent 'Plack::Middleware';

use Digest::HMAC_SHA1 'hmac_sha1_hex';
use HTTP::Status qw(:constants);

use Plack::Response;
use Plack::Util;
use Plack::Util::Accessor qw(
    blocked
    cookie_name
    logger
    parameter_name
    _token_generator
);

sub prepare_app {
    my $self = shift;

    $self->parameter_name('SEC') unless defined $self->parameter_name;

    # store the cookie_name
    $self->cookie_name(
        $self->cookie_name || 'PSGI-XSRF-Token'
    );

    $self->_token_generator(sub{
        my $data    = rand() . $$ . {} . time;
        my $key     = "@INC";
        my $digest  = hmac_sha1_hex($data, $key);
    });
}

sub call {
    my $self    = shift;
    my $env     = shift;

    # cache the logger
    $self->logger($env->{'psgix.logger'} || sub { })
        unless defined $self->logger;

    # we'll need the Plack::Request for this request
    my $request = Plack::Request->new($env);

    # grab the cookie where we store the token
    my $cookie = $request->cookies->{$self->cookie_name};

    # deal with form posts
$DB::single=1;
    if ($request->method =~ m{^post$}i) {
        $self->log(info => 'POST submitted');
        
        my $val = $request->parameters->{ $self->parameter_name } || '';
        return $self->xsrf_detected
            unless $val;
    }

    return Plack::Util::response_cb($self->app->($env), sub {
        my $res = shift;

        # we need to add our cookie
        $self->_set_cookie(
            $self->_token_generator->(),
            $res,
            path    => '/',
            expires => time + (3 * 60 * 60), # three hours into the future
        );

        return $res;
    });
}

sub xsrf_detected {
    my $self    = shift;
    my $env     = shift;

    $self->log(error => 'XSRF detected, returning HTTP_FORBIDDEN');

    if (my $app_for_blocked = $self->blocked) {
        return $app_for_blocked->($env, $@);
    }

    my $body = 'XSRF detected';
    return [
        HTTP_FORBIDDEN,
        [ 'Content-Type' => 'text/plain', 'Content-Length' => length($body) ],
        [ $body ]
    ];
}

sub log {
    my ($self, $level, $msg) = @_;
    $self->logger->({ level => $level, message => "XSRFBlock: $msg" });
}

# taken from Plack::Session::State::Cookie
# there's a very good reason why we have to do the cookie setting this way ...
# I just can't explain it clearly right now
sub _set_cookie {
    my($self, $id, $res, %options) = @_;
 
    # TODO: Do not use Plack::Response
    my $response = Plack::Response->new(@$res);
    $response->cookies->{ $self->cookie_name } = +{
        value => $id,
        %options,
    };
 
    my $final_r = $response->finalize;
    $res->[1] = $final_r->[1]; # headers
}

1;
# ABSTRACT: Block XSRF Attacks with minimal changes to your app
__END__
# vim: ts=8 sts=4 et sw=4 sr sta
