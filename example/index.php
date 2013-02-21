<?php

// Start the session
session_start();

// Include the OAuth-class
include("../oauth.class.php");

// Gather all OAuth-variables
$oauth_config['consumer_key']           = "abcdefghijklmopqrstuvwxyz";
$oauth_config['consumer_secret']        = "1234567890";
$oauth_config['request_token_endpoint'] = "https://example.com/oauth/request_token";
$oauth_config['request_token_callback'] = "http://localhost/oauth/example/index.php";
$oauth_config['authenticate_endpoint']  = "https://example.com/oauth/authenticate";
$oauth_config['access_token_endpoint']  = "https://example.com/oauth/access_token";

// Create an AOuth-object
$oauth = new OAuthClient($oauth_config['consumer_key'], $oauth_config['consumer_secret']);



if (!isset($_SESSION['oauth_token'])) {
    // The absolute beginning of the OAuth-dance.

    // Get an request-token
    $response = $oauth->request_token($oauth_config['request_token_endpoint'], $oauth_config['request_token_callback']);
    parse_str($response, $requestresponse);

    // Save the request tokens in the class and in the session
    $oauth->set_oauth_token($requestresponse['oauth_token']);
    $oauth->set_oauth_token_secret($requestresponse['oauth_token_secret']);

    $_SESSION['oauth_token'] = $requestresponse['oauth_token'];
    $_SESSION['oauth_token_secret'] = $requestresponse['oauth_token_secret'];

    header("Location: " . $oauth_config['authenticate_endpoint'] . "?oauth_token=" . $requestresponse['oauth_token']);
    exit(0);
}

if (isset($_GET['oauth_verifier'])) {
    // We are authenticated. Now lets get an access token.

    // Set the variables we need
    $oauth->set_oauth_token($_GET['oauth_token']);
    $oauth->set_oauth_verifier($_GET['oauth_verifier']);
    $oauth->set_oauth_token_secret($_SESSION['oauth_token_secret']);

    // Now get the acees-token
    $response = $oauth->access_token($oauth_config['access_token_endpoint']);
    parse_str($response, $accessresponse);

    // These are our definitive tokens:
    $oauth->set_oauth_token($accessresponse['oauth_token']);
    $oauth->set_oauth_token_secret($accessresponse['oauth_token_secret']);

    // With these tokens, we can do everything we want!
    $_SESSION['oauth_token'] = $accessresponse['oauth_token'];
    $_SESSION['oauth_token_secret'] = $accessresponse['oauth_token_secret'];

    header("Location: index.php");
    exit(0);
}

// If the authentication is done, we can use the tokens
$oauth->set_oauth_token($_SESSION['oauth_token']);
$oauth->set_oauth_token_secret($_SESSION['oauth_token_secret']);

$response = $oauth->call("https://example.com/api/get_some_lines.json", array("count" => 5));