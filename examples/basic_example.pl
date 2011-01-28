#!/usr/bin/perl
# Author: Michele Beltrame
# Original author: Dave Newquist
# License: perl6

use lib '../lib';

use strict;
use CGI::Carp qw/fatalsToBrowser/;
use CGI;
use CGI::Session;
use HTML::Tiny;

use Captcha::Peoplesign;

# Warbing: sample testing key (might not work)!
my $peoplesignKey = "5543333573134de45c8fdf9b4e8c1733";

# We create a name for this location (must match the one
# used when creating the key)
my $clientLocation = "PerlTest";

# peoplesign args: - getPeoplesignHTML accepts two ways of passing parameters:
#    array or challenge option string
#  e.g. default
my $peoplesignOptions = {};
#
#  e.g. pass an array
#my $peoplesignOptions = {
#    challengeType         => "pairThePhoto",
#    numPanels             => "2",
#    numSmallPhotos        => "8",
#    useDispersedPics      => "false",
#    smallPhotoAreaWidth   => ""
#};
#
#  e.g. pass a challenge_option_string - (obtained from peoplesign.com demo page)
#
my $peoplesignOptions = "language=english&useDispersedPics=false&numPanels=2&numSmallPhotos=6&useDragAndDrop=false&challengeType=pairThePhoto&category=(all)&hideResponseAreaWhenInactive=false";

# Pass { html_mode => 'xml' } if you use XHTML
my $ps = Captcha::Peoplesign->new();

my $query = CGI->new();
my $session = CGI::Session->new();
my $h = HTML::Tiny->new(mode => 'html');

if ( $ENV{REQUEST_METHOD} eq 'POST' ) {
    my $challengeSessionID = $query->param('challengeSessionID');
    my $challengeResponseString = $query->param('captcha_peoplesignCRS');
    
    #Use the peoplesign client the check the users's response
    my $res = $ps->check_answer(
        $peoplesignKey, $clientLocation, 
        $challengeSessionID, $challengeResponseString,
    );
    
    if ( $res->{is_valid} ) {
        print $session->header(
            -type       => 'text/html'
        );
        
        print _make_page($h->p([
            $h->strong('OK, you\'re human!')
        ]));
    } else {
        warn $res->{error};
        
        # Store this as we need to know the session ID after the redirect
        # it could also be passed via a GET parameter or so
        $session->param('challengeSessionID', $challengeSessionID);
        $session->flush();

        print $session->header(
            Location    => $ENV{HTTP_REFERER}
        );
    }
    
    exit 0;
}

my $challengeSessionID = $session->param('challengeSessionID') || '';

my $peoplesignHTML =  $ps->get_html(
    $peoplesignKey, $clientLocation, $peoplesignOptions, $challengeSessionID,
);

my $form = $h->form({
    method  => 'POST',
    action  => $query->request_uri,
}, [
    $peoplesignHTML,
    $h->input({
        type    => 'submit',
        value   => 'submit',
    }),
]);

print $session->header(
    -type       => 'text/html'
);
print _make_page($form);

exit 0;


sub _make_page {
    my $content = shift;
       
    my $html = '<!DOCTYPE HTML>';
    
    $html .= $h->html([
        $h->head([
            $h->meta({
                'http-equiv'    => 'pragma',
                'content'       => 'no-cache',
            }),
            $h->meta({
                'http-equiv'    => 'expires',
                'content'       => '-1',
            }),
            $h->meta({
                'http-equiv'    => 'content-type',
                'content'       => 'text/html; charset=UTF-8',
            }),
            $h->title('Peoplesign Perl integration demo'),
        ]),
        $h->body([
            $h->div({
                style   => 'width:500px; margin: 0 auto 0 auto',
            }, [
                $h->p('This page is a demonstration of the peoplesign perl plugin'),
                $content,
            ])
        ]),
    ]);
    
    return $html;
}
sub printExamplePageAndFormHeaders{
    print "content-type: text/html\n\n";
    print qq(
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
    <HTML>
    <!--
    Copyright 2008-2009, MyriComp LLC, All rights reserved.
    -->
    <HEAD>
	<META HTTP-EQUIV="Pragma" CONTENT="no-cache">
	<META HTTP-EQUIV="Expires" CONTENT="-1">
	<meta http-equiv="content-type" content="text/html; charset=UTF-8">
	<TITLE>peoplesign demo</TITLE>

    </HEAD>
    <BODY  style="width: 500px; margin-left: auto; margin-right:auto;">
    <div>
       <p>This page is a demonstration of the peoplesign perl plugin</p>
       <form method="post" action="$ENV{REQUEST_URI}">
    );
}

sub printExampleFormAndPageFooters {
    print qq(
       <input type="submit" value="submit">
       </form>
    </div
    );

    print qq(</BODY></HTML>);
}
