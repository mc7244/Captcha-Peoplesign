#!/usr/bin/perl
# Author: Michele Beltrame
# Original author: Dave Newquist
# License: perl6

use lib '../lib';

use strict;
use CGI::Carp qw/fatalsToBrowser/;
use CGI;

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

#*WARNING*!!!
#The function sends a cookie header to the
#browser, so you *MUST* call it before you print the page headers--
#especially the http "content-type: " header.
#
#If you're using CGI::header() or CGI::Session::header() to print your headers,
#the cookie header won't be sent properly.  There are two solutions.  The first
#is to manually print your headers after calling getPeoplesignHTML like we do
#in this example.

#If it's not possible to do that, you will need to look in the plugin file
#and understand what getPeoplesignHTML is doing, and write your own version
#that is compatible with the way your application handles sessions and cookies.
#In short, getPeoplesignHTML calls
#getPeoplesignSessionID (unless it finds a session id in the cookie),
#then calls getPeoplesignHTMLJavascript, then sends the cookie.
#Instead of using a cookie, you may want to use a session variable.
#Either way, **you must delete the session id when the user passes peoplesign.*
#
#The reason we store the session id (instead of getting a new one each time) is
#to allow peoplesign to automatically display a helpful message
#in the event a user doesn't pass on the first try.

my $ps = Captcha::Peoplesign->new();

if ( $ENV{REQUEST_METHOD} eq 'POST' ) {
    my $query = CGI->new();
    my $challengeSessionID = $query->param('challengeSessionID');
    my $challengeResponseString = $query->param('captcha_peoplesignCRS');
    
    #Use the peoplesign client the check the users's response
    my $allowPass = $ps->isPeoplesignResponseCorrect(
        $challengeSessionID,$challengeResponseString,
        $clientLocation, $peoplesignKey);
    
    if ($allowPass) {
        print "content-type: text/html\n\n";
        print "OK, you're human!";
    } else {
        $query->header(
            Location    => $ENV{HTTP_REFERER}
        );
    }
    
    exit 0;
}

my $peoplesignHTML =  $ps->getPeoplesignHTML(
    $peoplesignKey, $peoplesignOptions, $clientLocation
);

printExamplePageAndFormHeaders();
print $peoplesignHTML;
printExampleFormAndPageFooters();

exit 0;

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
       <form method="post" action="example2.pl">
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
