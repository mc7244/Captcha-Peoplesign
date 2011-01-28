package Captcha::Peoplesign;

use strict;
use warnings;

use Carp qw/croak/;
use HTML::Tiny;
use LWP::UserAgent;

use constant MODULE_VERSION => '0.00001';
our $VERSION = '0.00001';

use constant PEOPLESIGN_HOST => 'peoplesign.com';

use constant PEOPLESIGN_GET_CHALLENGE_SESSION_ID_URL =>
    'http://'.PEOPLESIGN_HOST.'/main/getChallengeSessionID';

use constant PEOPLESIGN_CHALLENGE_URL =>
    'http://'.PEOPLESIGN_HOST.'/main/challenge.html';

use constant PEOPLESIGN_GET_CHALLENGE_SESSION_STATUS_URL =>
    'http://'.PEOPLESIGN_HOST.'/main/getChallengeSessionStatus_v2';

use constant PEOPLESIGN_CHALLENGE_SESSION_ID_NAME => 'challengeSessionID';
use constant PEOPLESIGN_CHALLENGE_RESPONSE_NAME => 'captcha_peoplesignCRS';

use constant PEOPLESIGN_IFRAME_WIDTH => '335';
use constant PEOPLESIGN_IFRAME_HEIGHT => '335';

use constant PEOPLESIGN_CSID_SESSION_VAR_TIMEOUT_SECONDS => 3600;

use constant PEOPLESIGN_PLUGIN_VERSION => 'Captcha_Peoplesign_perl_' . MODULE_VERSION;

sub new {
    my $class = shift;
    my $self = bless {}, $class;

    my $args = shift || {};

    croak "new must be called with a reference to a hash of parameters"
        unless ref $args eq 'HASH';
        
    $self->{_html_mode} = $args->{html_mode} || 'html';

    return $self;
}

sub _html {
    my $self = shift;
    
    $self->{_html} ||= HTML::Tiny->new(
        mode => $self->{_html_mode}
    );
}

sub get_html {
    my $self = shift;
    my $peoplesignKey = shift || croak 'Provide a key';
    my $clientLocation = shift || croak 'Provide a location';
    my $peoplesignArgs = shift || croak 'Provide some arguments (even an empty string)';
    my $peoplesignSessionID = shift || '';
    my $pluginWrapperVersionInfo = shift || '';

    $clientLocation = $self->_clean_location_string($clientLocation);

    my $status = '';
    ($status, $peoplesignSessionID) = $self->_get_peoplesign_sessionid(
       $peoplesignKey,
       $ENV{REMOTE_ADDR},
       $peoplesignArgs,
       $clientLocation,
       $pluginWrapperVersionInfo,
       $peoplesignSessionID
    );

    if ($status eq 'success') {
        # An iframe will only be displayed if javascript is disabled
        # in the browser.
        my $iframeWidth = shift || PEOPLESIGN_IFRAME_WIDTH;
        my $iframeHeight = shift || PEOPLESIGN_IFRAME_HEIGHT;
        
        return $self->_get_html_js(
            $peoplesignSessionID,
            $iframeWidth,
            $iframeHeight,
        );
    }
    
    return "<p>peoplesign is unavailable ($status)</p>";
}


#description
##-calls getPeoplesignSessionStatus, refreshes the cookie expiration time

#parameters
##1)peoplesignKey
###-obtain your key from peoplesign.com

##2)client Location
###-MUST match the argument passed to get_html.

##3)peoplesignSessionID
###-get this from the request variable named 
### PEOPLESIGN_CHALLENGE_SESSION_ID_NAME
### when processing the form
###submission that included the peoplesign HTML.  It should have been passed
###as a hidden input.

##4)peoplesignResponseString
###-get this from the response variable named PEOPLESIGN_CHALLENGE_RESPONSE_NAME] when processing
### the form submission
### that included the peoplesign HTML.  It should have been passed as a hidden
###input.
###-if you are using getPeoplesignHTMLIFrame (rare)
### the request variable named PEOPLESIGN_CHALLENGE_RESPONSE_NAME won't be set

# Return value: hashref with is_valid (1 or 0) and error (if any)
sub check_answer {
    my $self = shift;
    my $peoplesignKey = shift || croak 'Provide a key';
    my $clientLocation = shift || croak 'Provide a location';
    my $peoplesignSessionID = shift || croak 'Provide challengeSessionID';
    my $peoplesignResponseString = shift || croak 'Provide response string';

    my $status = $self->_get_peoplesign_session_status(
        $peoplesignSessionID,
        $peoplesignResponseString,
        $clientLocation,
        $peoplesignKey
    );

    # If CAPTCHA is solved correcly, pass
    return { is_valid => 1 } if $status eq 'pass';

    # Usual states for which the user can not pass
    return { is_valid => 0, error => $status } if
        $status eq 'fail' || $status eq 'notRequested'
        || $status eq 'awaitingResponse';
    
    # If Peoplesign server has problems, do not pass but return
    # error so call decide if he/she wants to pass in such case
    return { is_valid => 0, error => $status }
        if $status eq 'badHTTPResponseFromServer';

    # If $status is invalidChallengeSessionID we can not allow the user to pass.
    # It's highly unusual for this to occur, and probably means the
    # peoplesignSession expired and the client session was still alive.
    # We now abandon this client session. This will trigger a new client session
    # and a new peoplesign session.
    return { is_valid => 0, error => $status . ' [' .$self->_get_caller_info_string() . ']' }
        if $status eq 'invalidChallengeSessionID';
        
    # All other cases are an exception, so croak!
    croak "Exception processing Peoplesign response: [status $status]"
        . $self->_get_caller_info_string();
}

# Contacts the peoplesign server to validate the user's response.
# Return: string ('pass', 'fail', 'awaitingResponse', 'badHTTPResponseFromServer')
sub _get_peoplesign_session_status {
    my $self = shift;
    my $peoplesignSessionID = shift || croak 'Provide challengeSessionID';
    my $peoplesignResponseString = shift || croak 'Provide response string';
    my $clientLocation = shift || "default";
    my $peoplesignKey = shift;

    $peoplesignResponseString = $self->_trim($peoplesignResponseString);

    my $ua = LWP::UserAgent->new();

    # Note that the constant values are referenced below using CONSTANT()
    # when they are needed as hash names. 
    my $response = $ua->post(
        PEOPLESIGN_GET_CHALLENGE_SESSION_STATUS_URL, {
            PEOPLESIGN_CHALLENGE_SESSION_ID_NAME()  => $peoplesignSessionID,
            PEOPLESIGN_CHALLENGE_RESPONSE_NAME()    => $peoplesignResponseString,
            privateKey                              => $peoplesignKey,
            clientLocation                          => $clientLocation
        }
    );

    return $self->_trim( $response->content )
        if ($response->is_success);
    
    $self->_print_error("bad HTTP response from server: " .$response ->status_line."\n", $self->_get_caller_info_string());
    return 'badHTTPResponseFromServer';
}

#return value
##array with 2 elements
###status
####
###peoplesignSessionID
####a peoplesignSessionID is assigned to a given visitor and is valid until it passes a challenge
sub _get_peoplesign_sessionid {
    my $self = shift;
    my $peoplesignKey = shift;
    my $visitorIP = shift;
    my $peoplesignOptions = shift;
    my $clientLocation = shift || "default";
    my $pluginWrapperVersionInfo = shift;
    my $peoplesignSessionID = shift;

    my $ua = LWP::UserAgent->new();

    my $status;

    # challenge option string
    if (ref($peoplesignOptions) ne "HASH") {
       my %hash = ();

       # decode the encoded string into a hash
       $peoplesignOptions = $self->_html->url_decode($peoplesignOptions);
       foreach my $pair (split("&",$peoplesignOptions)){
           my ($key,$value) = split("=", $pair);
           $hash{$key} = $value;
        }
        $peoplesignOptions = \%hash;
    }

    $peoplesignKey = $self->_trim($peoplesignKey);
    $visitorIP  = $self->_trim($visitorIP);
 
    # Ensure private key is not the empty string
    if ($peoplesignKey eq "") {
        $self->_print_error("received a private key that was all whitespace or empty\n", $self->_get_caller_info_string());
        return ("invalidPrivateKey", "");
    }

    # Ensure visitorIP is ipv4
    if ( !($visitorIP =~ /^\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?$/) ) {
        $self->_print_error("invalid visitorIP: $visitorIP\n", $self->_get_caller_info_string());
        return ("invalidVisitorIP", "");
    }

    my $response = $ua->post(
        PEOPLESIGN_GET_CHALLENGE_SESSION_ID_URL, {
            privateKey                              => $peoplesignKey,
            visitorIP                               => $visitorIP,
            clientLocation                          => $clientLocation,
            pluginInfo                              => $pluginWrapperVersionInfo
                .' '.PEOPLESIGN_PLUGIN_VERSION,
            PEOPLESIGN_CHALLENGE_SESSION_ID_NAME()  => $peoplesignSessionID,
            %{$peoplesignOptions},
        }
    );

   if ($response->is_success){
        ($status, $peoplesignSessionID) = split(/\n/, $response->content);
        if ($status ne 'success') {
            $self->_print_error("Unsuccessful attempt to get a peoplesign "
                ."challenge session: ($status)\n", $self->_get_caller_info_string());
        }
   } else {
        $self->_print_error("bad HTTP response from server:  "
            . $response ->status_line."\n", $self->_get_caller_info_string());
        $status = "invalidServerResponse";
        $peoplesignSessionID = "";
   }

    return ($status, $peoplesignSessionID);
}


sub _get_html_js {
    my $self = shift;
    my $peoplesignSessionID = shift;

    # iframe will only be displayed if javascript is disabled in browser
    my $iframeWidth = shift || PEOPLESIGN_IFRAME_WIDTH;
    my $iframeHeight = shift || PEOPLESIGN_IFRAME_HEIGHT;

    if ( $peoplesignSessionID eq "" ) {return "";}

    my $h = $self->_html;

    my $htmlcode = $h->script({
        type    => 'text/javascript',
        src     => PEOPLESIGN_CHALLENGE_URL . '?' . PEOPLESIGN_CHALLENGE_SESSION_ID_NAME
            . '=' . $peoplesignSessionID . '&addJSWrapper=true&ts=\''
            . '+\(new Date\(\)\).getTime\(\) +\'" id="yeOldePeopleSignJS">'
    })
    . $h->noscript(
        $self->_get_html_iframe($peoplesignSessionID, $iframeWidth, $iframeHeight)
    );

    return $htmlcode;
}

sub _get_html_iframe {
    my $self = shift;
    my $peoplesignSessionID = shift;
    my $width = shift || PEOPLESIGN_IFRAME_WIDTH;
    my $height = shift || PEOPLESIGN_IFRAME_HEIGHT;
    if ( $peoplesignSessionID eq "") {return "";}
    
    my $h = $self->_html;

    my $htmlcode = $h->iframe({
        src                 => PEOPLESIGN_CHALLENGE_URL . '?' . PEOPLESIGN_CHALLENGE_SESSION_ID_NAME,
        height              => $width,
        width               => $height,
        frameborder         => 0,
        allowTransparency   => 'true',
        scrolling           => 'auto',
      },
      $h->p(
        'Since it appears your browser does not support "iframes", you need to click '
        . $h->a({
            href    => PEOPLESIGN_CHALLENGE_URL
        }, 'here')
        . ' to verify you\'re a human.'
      )
      . $h->input({
          name  => PEOPLESIGN_CHALLENGE_SESSION_ID_NAME,
          type  => 'hidden',
          value => $peoplesignSessionID,
      })
    );
    
    return $htmlcode;
}

sub _clean_location_string{
    my $self = shift;
    #perl's session and cookie libraries will clean this string for us
    my $returnValue = shift;
    return $returnValue;
}

sub _get_caller_info_string {
    my $self = shift;
    #For the second subroutine up the call stack return the following:
    #file: subroutine:  line number
    return (caller(2))[1] .": " .(caller(2))[3] .": line " .(caller(2))[2];
}

sub _print_error {
    my $self = shift;
    my $message = shift;

    #if an error source was passed here, print it.  Else
    #we have to determine it;
    my $errorSourceInfo = shift || $self->_get_caller_info_string();

    print STDERR "ERROR: peoplesign client: $errorSourceInfo: $message\n";
    return;
}

sub _trim {
    my ($self, $string) = @_;
    $string =~ s/^\s*//;
    $string =~ s/\s*$//;
    return $string;
}

1;
__END__

=head1 NAME

Captcha::Peoplesign - Easily integrate Peoplesign CAPTCHA in your
Perl application

=head1 SYNOPSIS

    use Captcha::Peoplesign;

    my $ps = Captcha::Peoplesign->new;

    # Output form
    print $ps->get_html(
        'your_key', 'your_location'
        'options_string', 'challengeSessionID',
    );

    # Verify submission
    my $result = $ps->check_answer(
        'your_key', 'your_location',
        $challengeSessionID, $challengeResponseString,
    );
    );

    if ( $result->{is_valid} ) {
        print "You're human!";
    }
    else {
        # Error
        $error = $result->{error};
    }

For some examples, please see the /examples subdirectory

=head1 DESCRIPTION

Peoplesign is a clever CAPTCHA system which is quite a departure
from the standard ones where you need to guess a difficult word.

To use Peoplesign you need to register your site here:

L<https://peoplesign.com>

=head1 INTERFACE

TODO-TODO-TODO

=over

=item C<< new >> 

Arguments: \%args

Create a new C<< Captcha::Peoplesign >> object.

=over

=item C<< html_mode >>

Sets what kind of HTML the library generates. Default is 'html',
since we are going toward HTML5, but you can pass 'xml' if you
use XHTML.

=back

=item C<< get_html( $pubkey, $error, $use_ssl, $options ) >>

Generates HTML to display the captcha.

    print $captcha->get_html( $PUB, $err );

=over

=item C<< $pubkey >>

Your reCAPTCHA public key, from the API Signup Page

=item C<< $error >>

Optional. If set this should be either a string containing a reCAPTCHA
status code or a result hash as returned by C<< check_answer >>.

=item C<< $use_ssl >>

Optional. Should the SSL-based API be used? If you are displaying a page
to the user over SSL, be sure to set this to true so an error dialog
doesn't come up in the user's browser.

=item C<< $options >>

Optional. A reference to a hash of options for the captcha. See 
C<< get_options_setter >> for more details.

=back

Returns a string containing the HTML that should be used to display
the captcha.

=item C<< get_options_setter( $options ) >>

You can optionally customize the look of the reCAPTCHA widget with some
JavaScript settings. C<get_options_setter> returns a block of Javascript
wrapped in <script> .. </script> tags that will set the options to be used
by the widget.

C<$options> is a reference to a hash that may contain the following keys:

=over

=item C<theme>

Defines which theme to use for reCAPTCHA. Possible values are 'red',
'white' or 'blackglass'. The default is 'red'.

=item C<tabindex>

Sets a tabindex for the reCAPTCHA text box. If other elements in the
form use a tabindex, this should be set so that navigation is easier for
the user. Default: 0.

=back

=item C<< check_answer >>

After the user has filled out the HTML form, including their answer for
the CAPTCHA, use C<< check_answer >> to check their answer when they
submit the form. The user's answer will be in two form fields,
recaptcha_challenge_field and recaptcha_response_field. The reCAPTCHA
library will make an HTTP request to the reCAPTCHA server and verify the
user's answer.

=over

=item C<< $privkey >>

Your reCAPTCHA private key, from the API Signup Page.

=item C<< $remoteip >>

The user's IP address, in the format 192.168.0.1.

=item C<< $challenge >>

The value of the form field recaptcha_challenge_field

=item C<< $response >>

The value of the form field recaptcha_response_field.

=back

Returns a reference to a hash containing two fields: C<is_valid>
and C<error>.

    my $result = $c->check_answer(
        'your private key here', $ENV{'REMOTE_ADDR'},
        $challenge, $response
    );

    if ( $result->{is_valid} ) {
        print "Yes!";
    }
    else {
        # Error
        $error = $result->{error};
    }

See the /examples subdirectory for examples of how to call C<check_answer>.

=back

=head1 CONFIGURATION

To use Peoplesign sign up for a key here:

L<http://peoplesign.com>

=head1 AUTHOR

Andy Armstrong  C<< <andy@hexten.net> >>

=head1 LICENSE AND COPYRIGHT

Copyright (c) 2011, Michele Beltrame C<< <mb@italpro.net> >>.

Heavily based on the original Peoplesign Perl library by David B. Newquist.

Interface taken from L<Captch::reCAPTCHA> module by Andy Armstrong.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl 5 itself. See L<perlartistic>.
