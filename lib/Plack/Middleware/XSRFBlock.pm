package Plack::Middleware::XSRFBlock;
use strict;
use warnings;
use parent 'Plack::Middleware';

use Digest::HMAC_SHA1 'hmac_sha1_hex';
use HTML::Parser;
use HTTP::Status qw(:constants);

use Plack::Response;
use Plack::Util;
use Plack::Util::Accessor qw(
    blocked
    cookie_name
    logger
    meta_tag
    parameter_name
    _token_generator
);

sub prepare_app {
    my $self = shift;

    $self->parameter_name('xsrf_token') unless defined $self->parameter_name;

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
    my $cookie_value = $request->cookies->{$self->cookie_name};

    # deal with form posts
    if ($request->method =~ m{^post$}i) {
        $self->log(info => 'POST submitted');

        my $val = $request->parameters->{ $self->parameter_name } || '';

        # it's an immediate fail if we can't find the parameter
        return $self->xsrf_detected({ msg => 'form field missing'})
            unless $val;

        # get the value we expect from the cookie
        return $self->xsrf_detected({ msg => 'cookie missing'})
            unless defined $cookie_value;

        # reject if the form value and the token don't match
        return $self->xsrf_detected({ msg => 'invalid token'})
            if $val ne $cookie_value;
    }

    return Plack::Util::response_cb($self->app->($env), sub {
        my $res = shift;

        my $token = $cookie_value ||= $self->_token_generator->();

        # we need to add our cookie
        $self->_set_cookie(
            $token,
            $res,
            path    => '/',
            expires => time + (3 * 60 * 60), # three hours into the future
        );

        # we can't form-munge anything non-HTML
        my $ct = Plack::Util::header_get($res->[1], 'Content-Type') || '';
        if($ct !~ m{^text/html}i and $ct !~ m{^application/xhtml[+]xml}i){
            return $res;
        }

        # let's inject our field+token into the form
        my @out;
        my $http_host = $request->uri->host;
        my $parameter_name = $self->parameter_name;

        my $p = HTML::Parser->new( api_version => 3 );

        $p->handler(default => [\@out , '@{text}']),

        # we only care about two types of tag:
        $p->report_tags(qw/head form/);

        # inject out xSRF information
        $p->handler(
            start => sub {
                my($tag, $attr, $text) = @_;
                # we never want to thrown anything away
                push @out, $text;

                # for easier comparison
                $tag = lc($tag);

                # If we found the head tag and we want to add a <meta> tag
                if( $tag eq 'head' && $self->meta_tag) {
                    # Put the csrftoken in a <meta> element in <head>
                    # So that you can get the token in javascript in your
                    # App to set in X-CSRF-Token header for all your AJAX
                    # Requests
                    push @out,
                        sprintf(
                            q{<meta name="%s" content="$s"/>},
                            $self->meta_tag,
                            $token
                        );
                }

                # If tag isn't 'form' and method isn't 'post' we dont care
                return unless $tag eq 'form' && $attr->{'method'} =~ /post/i;

                if(
                    !(
                        $attr->{'action'} =~ m{^https?://([^/:]+)[/:]}
                            and
                        $1 ne $http_host
                    )
                ) {
                    push @out,
                        sprintf(
                            '<input type="hidden" "name="%s" value="%s" />',
                            $parameter_name,
                            $token
                        );
                }

                # TODO: determine xhtml or html?
                return;
            },
            "tagname, attr, text",
        );

        my $done;
        return sub {
            return if $done;

            if(defined(my $chunk = shift)) {
                $p->parse($chunk);
            }
            else {
                $p->eof;
                $done++;
            }
            join '', splice @out;
        }
    });
}

sub xsrf_detected {
    my $self    = shift;
    my $args    = shift;
    my $env = $args->{env};
    my $msg = $args->{msg}
        ? sprintf('XSRF detected [%s]', $args->{msg})
        : 'XSRF detected';

    $self->log(error => 'XSRF detected, returning HTTP_FORBIDDEN');

    if (my $app_for_blocked = $self->blocked) {
        return $app_for_blocked->($env, $@);
    }

    return [
        HTTP_FORBIDDEN,
        [ 'Content-Type' => 'text/plain', 'Content-Length' => length($msg) ],
        [ $msg ]
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

=head1 DESCRIPTION

This middleware blocks XSRF. You can use this middleware without any
modifications to your application.

=head1 EXPLANATION

This module is similar in nature and intention to
L<Plack::Middleware::CSRFBlock> but implements the xSRF prevention in a
different manner.

The solution implemented in this module is based on a CodingHorror article -
L<Preventing CSRF and XSRF Attacks|http://www.codinghorror.com/blog/2008/10/preventing-csrf-and-xsrf-attacks.html>.

The driving comment behind this implementation is from
L<the Felten and Zeller paper|https://www.eecs.berkeley.edu/~daw/teaching/cs261-f11/reading/csrf.pdf>:

    When a user visits a site, the site should generate a
    (cryptographically strong) pseudorandom value and set it as
    a cookie on the user's machine. The site should require
    every form submission to include this pseudorandom value as
    a form value and also as a cookie value. When a POST request
    is sent to the site, the request should only be considered
    valid if the form value and the cookie value are the same.
    When an attacker submits a form on behalf of a user, he can
    only modify the values of the form. An attacker cannot read
    any data sent from the server or modify cookie values, per
    the same-origin policy.  This means that while an attacker
    can send any value he wants with the form, he will be unable
    to modify or read the value stored in the cookie. Since the
    cookie value and the form value must be the same, the
    attacker will be unable to successfully submit a form unless
    he is able to guess the pseudorandom value.

=head2 What's wrong with Plack::Middleware::CSRFBlock?

L<Plack::Middleware::CSRFBlock> is a great module.
It does a great job of preventing CSRF behaviour with minimal effort.

However when we tried to use it uses the session to store information - which
works well most of the time but can cause issues with session timeouts or
removal (for any number of valid reasons) combined with logging (back) in to
the application in another tab (so as not to interfere with the current
screen/tab state).

Trying to modify the existing module to provide the extra functionality and
behaviour we decided worked better for our use seemed too far reaching to try
to force into the existing module.

=head2 SEE ALSO

L<Plack::Middleware::CSRFBlock>,
L<Plack::Middleware>,
L<Plack>

=cut

# ABSTRACT: Block XSRF Attacks with minimal changes to your app
__END__
# vim: ts=8 sts=4 et sw=4 sr sta
