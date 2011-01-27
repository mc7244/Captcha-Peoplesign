package Captcha::Peoplesign;

use strict;
use warnings;

use Carp qw/croak/;

use CGI;
use CGI::Cookie;
use HTML::Tiny;
use LWP::UserAgent;

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

use constant PEOPLESIGN_PLUGIN_VERSION => 'Captcha_Peoplesign_perl_' . $VERSION;

sub new {
  my $class = shift;
  my $self = bless {}, $class;
  $self->_initialize( @_ );
  return $self;
}

sub _initialize {
  my $self = shift;
  my $args = shift || {};

  croak "new must be called with a reference to a hash of parameters"
   unless 'HASH' eq ref $args;
}

sub _html { shift->{_html} ||= HTML::Tiny->new }

sub getPeoplesignHTML {
    my $self = shift;
    my $peoplesignKey = shift;
    my $peoplesignArgs = shift;

    my $clientLocation = shift || "default";
    my $pluginWrapperVersionInfo = shift || '';

    #an iframe will only be displayed if javascript is disabled
    #in the browser.
    my $iframeWidth = shift || PEOPLESIGN_IFRAME_WIDTH;
    my $iframeHeight = shift || PEOPLESIGN_IFRAME_HEIGHT;

    my $peoplesignHTML = "";
    my $status = "";
    my $peoplesignSessionID = "";

    $clientLocation = $self->cleanLocationString($clientLocation);

    $peoplesignSessionID = $self->getPSCookieValue($clientLocation);

    ($status, $peoplesignSessionID) = $self->getPeoplesignSessionID(
	   $peoplesignKey,
	   $ENV{REMOTE_ADDR},
	   $peoplesignArgs,
	   $clientLocation,
	   $pluginWrapperVersionInfo,
	   $peoplesignSessionID);
    

    if ($status eq "success") {
	#an iframe will only be displayed if javascript is disabled
	#in the browser
	$peoplesignHTML = $self->getPeoplesignHTMLJavaScript($peoplesignSessionID,
	                                              $iframeWidth,
	                                              $iframeHeight);
    } else {
	$peoplesignHTML = "<p>peoplesign is unavailable ($status)</p>";
    }
    $self->printPSCookie($clientLocation, $peoplesignSessionID);

    return $peoplesignHTML;
}
######################
#isPeoplesignResponseCorrect
######################

#usageNotes
##-call this when processing the user's response to peoplesign ONLY if you 
## setup peoplesign with getPeoplesignHTML

#description
##-looks for peoplesignSessionID and peoplesignResponseString in the request 
## variables
## array unless you pass them as arguments.
##-calls processPeoplesignResponse
##-sends a cookie header.  The cookie containing the peoplesign session 
## is refreshed if it's still needed, otherwise it's set to empty string and
## is expired.

#parameters
##1)peoplesignSessionID
###-this should have been included (named PEOPLESIGN_CHALLENGE_SESSION_ID_NAME)
### as form data (usually found in http post data) from the form
### that included the peoplesign HTML.  It should have been passed
### as a hidden input.
### If you pass null or empty string, the routine will attempt to find it. 

##2)peoplesignResponseString
###-this should should have been passed as a hidden
### input in the same form mentioned above.  The 
###-if you are using getPeoplesignHTMLIFrame (rare)
### request variable named PEOPLESIGN_CHALLENGE_RESPONSE_NAME 
### won't be set, but the user's 
### browser will have already sent it to the peoplesign server.

##3)client Location
###-MUST match the argument passed to getPeoplesignHTML.

##4)peoplesignKey
###-obtain your key from peoplesign.com

#return value
##1 or 0
sub isPeoplesignResponseCorrect {
    my $self = shift;
    my $peoplesignSessionID = shift;
    my $peoplesignResponseString = shift;
    my $clientLocation = shift || "default";
    my $peoplesignKey = shift;

    my $status = "";

    $clientLocation = $self->cleanLocationString($clientLocation);

    $peoplesignSessionID = $self->trim($peoplesignSessionID);

    #The passed in value for peoplesignSessionID has highest priority.
    #Try to find it in the HTTP Post/Get if it's not present
    my $cgi;
    if (!$peoplesignSessionID){
	$cgi = CGI::new();
	$peoplesignSessionID =$cgi->param(PEOPLESIGN_CHALLENGE_SESSION_ID_NAME);
    }

    if (!$peoplesignResponseString){
	if (!$cgi) {$cgi = CGI::new();}
	$peoplesignResponseString = 
	    $cgi->param(PEOPLESIGN_CHALLENGE_RESPONSE_NAME);
	
    }

    if (!$peoplesignSessionID) {
	$self->printError("Can't find peoplesignSessionID in "
		   ."isPeoplesignResponseCorrect.", $self->getCallerInfoString());
    }

    my $allowPass = $self->processPeoplesignResponse(
       $peoplesignSessionID,$peoplesignResponseString,
	$clientLocation, $peoplesignKey);
   
    $self->printPSCookie($clientLocation, $peoplesignSessionID);
    

    return $allowPass;
}

######################
#processPeoplesignResponse
######################

#usageNotes
##-use this (instead of isPeoplesignResponseCorrect) if your application
## is using CGI::Session or if it has already sent http headers before 
## it checks the peoplesign response
##-use the first element of the return value (an array) to determine if the 
## user's response is correct.
##-use the second element of the return value to determine if you need to 
## persist the peoplesign session id using a session variable or cookie.

#description
##-calls getPeoplesignSessionStatus, refreshes the cookie expiration time

#parameters
##1)peoplesignSessionID
###-get this from the request variable named 
### PEOPLESIGN_CHALLENGE_SESSION_ID_NAME
### when processing the form
###submission that included the peoplesign HTML.  It should have been passed
###as a hidden input.

##2)peoplesignResponseString
###-get this from the response variable named PEOPLESIGN_CHALLENGE_RESPONSE_NAME] when processing
### the form submission
### that included the peoplesign HTML.  It should have been passed as a hidden
###input.
###-if you are using getPeoplesignHTMLIFrame (rare)
### the request variable named PEOPLESIGN_CHALLENGE_RESPONSE_NAME won't be set

##3)client Location
###-MUST match the argument passed to getPeoplesignHTML.

##4)peoplesignKey
###-obtain your key from peoplesign.com

#return value
###element 1: isResponseCorrect (1 or 0)

sub processPeoplesignResponse {
    my $self = shift;
    my $peoplesignSessionID = shift;
    my $peoplesignResponseString = shift;
    my $clientLocation = shift || "default";
    my $peoplesignKey = shift;

    my $cgi;
    if (!$peoplesignSessionID){
	$cgi = CGI::new();
	$peoplesignSessionID =$cgi->param(PEOPLESIGN_CHALLENGE_SESSION_ID_NAME);
    }

    if (!$peoplesignResponseString){
	if (!$cgi) {$cgi = CGI::new();}
	$peoplesignResponseString = 
	    $cgi->param(PEOPLESIGN_CHALLENGE_RESPONSE_NAME);
	
    }


    my $status = $self->getPeoplesignSessionStatus($peoplesignSessionID,
                                     $peoplesignResponseString,
                                     $clientLocation,
                                     $peoplesignKey);

    my $allowPass = 0;
    #storePSID is no longer used.
    my $storePSID = 0;

    if ($status eq "pass") {
	$allowPass = 1; $storePSID = 0;
    } elsif ( ($status eq "fail") || ($status eq "notRequested") ||
	      ($status eq "awaitingResponse") ) {

	$allowPass = 0; $storePSID = 1;
    #If $status is invalidChallengeSessionID we can not allow the user to pass.
    #It's highly unusual for this to occur, and probably means the
    #peoplesignSession expired and the client session was still alive.
    #We now abandon this client session. This will trigger a new client session
    #and a new peoplesign session.
    } elsif ( $status eq "invalidChallengeSessionID"){
	$self->printError("getPeoplesignSessionStatus returned "
		  ."invalidChallengeSessionID", $self->getCallerInfoString());
	$allowPass = 0; $storePSID = 0;
    #let the user pass if there's a problem with the peoplesign server
    } elsif ($status eq "badHTTPResponseFromServer") {
	$allowPass = 1; $storePSID = 0;
    } else {
	$allowPass = 1; $storePSID = 0;
    }

    return $allowPass;

}

######################
#getPeoplesignSessionStatus
######################
#Description
##Contacts the peoplesign server to validate the user's response.
#Return value
##a string, usually pass, fail or awaitingResponse
#Parameters
##identical to those of canUserPass

sub getPeoplesignSessionStatus {
    my $self = shift;
    my $peoplesignSessionID = shift;
    my $peoplesignResponseString = shift;
    my $clientLocation = shift || "default";
    my $peoplesignKey = shift;

    #Find peoplesignResponseString
    $peoplesignResponseString = $self->trim($peoplesignResponseString);

    if (!$peoplesignResponseString) {
	my $cgi = CGI::new();
	$peoplesignResponseString =
	    $cgi->param(PEOPLESIGN_CHALLENGE_RESPONSE_NAME);
    }

    my $status = "";

    my $userAgent = LWP::UserAgent->new();

    #Note that the constant values are referenced below using CONSTANT()
    #when they are needed as hash names. 
    my $response = $userAgent->post(
                      PEOPLESIGN_GET_CHALLENGE_SESSION_STATUS_URL, 
                      {
	                PEOPLESIGN_CHALLENGE_SESSION_ID_NAME() => 
			    $peoplesignSessionID,
                        PEOPLESIGN_CHALLENGE_RESPONSE_NAME() =>
			    $peoplesignResponseString,
			privateKey => $peoplesignKey,
			clientLocation => $clientLocation
                      }
    );

    if ($response->is_success){
	$status = $response->content;
	$status = $self->trim($status);
    } else {
	$self->printError("bad HTTP response from server: " .$response ->status_line."\n", $self->getCallerInfoString());
	$status = "badHTTPResponseFromServer";
    }
    return $status;
}

######################
#getPeoplesignSessionID
######################
#return value
##array with 2 elements
###status
####
###peoplesignSessionID
####a peoplesignSessionID is assigned to a given visitor and is valid until it passes a challenge

sub getPeoplesignSessionID {
    my $self = shift;
    my $peoplesignKey = shift;
    my $visitorIP = shift;
    my $peoplesignOptions = shift;
    my $clientLocation = shift || "default";
    my $pluginWrapperVersionInfo = shift;
    my $peoplesignSessionID = shift;

    my $userAgent = LWP::UserAgent->new();

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

    $peoplesignKey = $self->trim($peoplesignKey);
    $visitorIP  = $self->trim($visitorIP);
    #ensure private key is not the empty string
    if ($peoplesignKey eq "") {
	$self->printError("received a private key that was all whitespace or empty\n", $self->getCallerInfoString());
	return ("invalidPrivateKey", "");
    }

    #ensure visitorIP is ipv4
    if ( !($visitorIP =~ /^\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?$/)) {
	$self->printError("invalid visitorIP: $visitorIP\n", $self->getCallerInfoString());
	return ("invalidVisitorIP", "");
    }


    my $response = $userAgent->post(PEOPLESIGN_GET_CHALLENGE_SESSION_ID_URL, {
	                privateKey => $peoplesignKey,
			visitorIP => $visitorIP,
			%{$peoplesignOptions},
			clientLocation => $clientLocation,
			pluginInfo => $pluginWrapperVersionInfo
			                 ." ".PEOPLESIGN_PLUGIN_VERSION,
			PEOPLESIGN_CHALLENGE_SESSION_ID_NAME() 
			    => $peoplesignSessionID
    });

   if ($response->is_success){
       ($status, $peoplesignSessionID) = split(/\n/, $response->content);
       if ($status ne "success") {
	   $self->printError("Unsuccessful attempt to get a peoplesign "
		     ."challenge session: ($status)\n", $self->getCallerInfoString());
       } else{

       }
   } else {
       $self->printError("bad HTTP response from server:  "
                  .$response ->status_line."\n", $self->getCallerInfoString());
       $status = "invalidServerResponse";
       $peoplesignSessionID = "";
   }

    return ($status, $peoplesignSessionID);
}


#The HTML returned will tell the browser to use the javascript version if 
#possible.  If not, it will use the iframe version.
sub getPeoplesignHTMLJavaScript {
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
        $self->getPeoplesignHTMLIFrame($peoplesignSessionID, $iframeWidth, $iframeHeight)
    );

    return $htmlcode;
}
#use this if you're sure you want the iframe version of the peoplesign widget 
#and never the javascript version
sub getPeoplesignHTMLIFrame{
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

################################################
#web internal subroutines
################################################
sub getPSCookieValue {
    my $self = shift;
    my $clientLocation = shift || "default";
    my $cgi = CGI::new();
    return $cgi->cookie("psClient_$clientLocation");
}

sub printPSCookie {
    my $self = shift;
    my $clientLocation = shift;
    my $cookieValue = shift;
    my $doExpire = shift;

    my $expireValue = '+'.PEOPLESIGN_CSID_SESSION_VAR_TIMEOUT_SECONDS.'s';
    if ($doExpire eq "expire"){
	$expireValue = "now";
    }

    my $cookie = CGI::Cookie->new(-name => "psClient_$clientLocation",
				   -value => $cookieValue,
				   -expires => $expireValue);

    #$cookie->bake();
    print "Set-Cookie: $cookie\n";
    return;
}


################################################
#misc internal subroutines
################################################
sub cleanLocationString {
    my $self = shift;
    #perl's session and cookie libraries will clean this string for us
    my $returnValue = shift;
    return $returnValue;
}

sub getCallerInfoString {
    my $self = shift;
    #For the second subroutine up the call stack return the following:
    #file: subroutine:  line number
    return (caller(2))[1] .": " .(caller(2))[3] .": line " .(caller(2))[2];
}

sub printErrorAndExit {
    my $self = shift;
    my $message = shift;

    #if an error source was passed here, print it.  Else
    #we have to determine it;
    my $errorSourceInfo = shift || $self->getCallerInfoString();

    $self->printError($message, $errorSourceInfo);
    print "content-type: text/html\n\n";
    print "ERROR: peoplesign client: $errorSourceInfo: $message\n";
    exit(1);
}

sub printError {
    my $self = shift;
    my $message = shift;

    #if an error source was passed here, print it.  Else
    #we have to determine it;
    my $errorSourceInfo = shift || $self->getCallerInfoString();

    print STDERR "ERROR: peoplesign client: $errorSourceInfo: $message\n";
    return;
}

sub trim {
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
    print $c->get_html( 'you_key', 'your_location' );

    # Verify submission
    my $result = $c->check_answer(
        'your_key', 'your_submission',
        $challenge, $response
    );

    if ( $result->{is_valid} ) {
        print "Yes!";
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

=over

=item C<< new >>

Create a new C<< Captcha::reCAPTCHA >>.

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

Based on the original Peoplesign Perl library by David B. Newquist.

Interface taken from L<Captch::reCAPTCHA> module by Andy Armstrong.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.
