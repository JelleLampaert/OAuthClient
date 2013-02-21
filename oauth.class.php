<?php

/**
 *
 * @author      Jelle Lampaert
 * @version     0.2
 * @license     BSD License
*/

class OAuthClient {

    /*
     * The application's consumer key
     */
    private $consumer_key;
    
    /*
     * The application's secret key
     */
    private $consumer_secret;
    
    /*
     * The url to receive a request token
     */
    private $request_token_endpoint;
    
    /*
     * The url to receive an access token
     */
    private $access_token_endpoint;
    
    /*
     * The OAuth version we want to use
     */
    private $version;
    
    /*
     * The OAuth signing method
     */
    private $signature_method;
    
    /*
     * A non-variable nonce for testing purposes
     */
    private $nonce;
    
    /*
     * The OAuth token secret, which we got after a request_token
     */
    private $oauth_token_secret;
    
    /*
     * The OAuth token, which we got after a request_token
     */
    private $oauth_token;
    
    /*
     * The variable in which to store all curl-stuff
     */
    private $curl;
    
    /*
     * The error-class
     */
    private $error;
    
    /*
     * The OAuth verifier
     */
    private $oauth_verifier;
    
    /*
     * The constructor of our OAuth-class.
     * Set the keys if possible
     *
     * @return  void
     * @param   string  $consumer_key      The consumer key to use
     * @param   string  $consumer_secret   The consumer secret to use
     */
    public function __construct($consumer_key, $consumer_secret) {
        $this->consumer_key = $consumer_key;
        $this->consumer_secret = $consumer_secret;
        $this->version = "1.0";                 // Variable needed for future use
        $this->signature_method = "HMAC-SHA1";
    }
    
    /*
     * Receive a request token
     *
     * @return  string
     * @param   string  $endpoint  The endpoint to obtain a request token
     * @param   string  $callback  The callback URL if one is needed in the request
     */
    public function request_token($endpoint, $callback = null) {
        $this->request_token_endpoint = $endpoint;
        
        $options = array();
        if ($callback) {
            $options['oauth_callback'] = $callback;
        }
        
        return $this->call($endpoint, $options, "GET");
    }
    
    /*
     * Receive an access token
     *
     * @return  string
     * @param   string  $endpoint  The endpoint to obtain an access token
     */
    public function access_token($endpoint) {
        return $this->call($endpoint, array("oauth_token" => $this->oauth_token, "oauth_verifier" => $this->oauth_verifier), "GET");
    }
    
    /*
     * Set the consumer key
     *
     * @return  void
     * @param   $string  $consumer_key  The consumer key
     */
    public function set_consumer_key($consumer_key) {
        $this->consumer_key = $consumer_key;
    }
    
    /*
     * Set the consumer secret
     *
     * @return  void
     * @param   string  $consumer_secret  The consumer secret
     */
    public function set_consumer_secret($consumer_secret) {
        $this->consumer_secret = $consumer_secret;
    }
    
    /*
     * Set the OAuth token
     *
     * @return  void
     * @param   string  $oauth_token  The OAuth token
     */
    public function set_oauth_token($oauth_token) {
        $this->oauth_token = $oauth_token;
    }
    
    /*
     * Set the OAuth token secret
     *
     * @return  void
     * @param   string  $oauth_token_secret  The OAuth token secret
     */
    public function set_oauth_token_secret($oauth_token_secret) {
        $this->oauth_token_secret = $oauth_token_secret;
    }
    
    /*
     * Set the OAuth verifier
     *
     * @return  void
     * @param   string  $oauth_verifier  The OAuth verifier
     */
    public function set_oauth_verifier($oauth_verifier) {
        $this->oauth_verifier = $oauth_verifier;
    }
    
    /*
     * Set the nonce (for testing purposes only!)
     *
     * @return  void
     * @param   string  $nonce  The nonce
     */
    public function set_nonce($nonce) {
        $this->nonce = $nonce;
    }
    
    /*
     * Set the signing method.
     * Currently supports HMAC-SHA1 and PLAINTEXT
     *
     * @return  void
     * @param   string  $signing  The signing method
     */
    public function set_signature_method($signing) {
        $signing = strtoupper($signing);
        
        switch ($signing) {
            case "PLAINTEXT":
                $this->signature_method = $signing;
                break;
            default:
                $this->signature_method = "HMAC-SHA1";
        }
    }
    
    /*
     * Do the OAuth call
     *
     * @return  string
     * @param   string  $url         The url where we want to request something
     * @param   array   $parameters  The parameters our request needs to contain
     */
    public function call($url, array $parameters = array(), $method = "GET") {
        
        // Append the default parameters
        $parameters['oauth_consumer_key'] = $this->consumer_key;
        $parameters['oauth_nonce'] = isset($this->nonce) ? $this->nonce : md5(rand() . microtime() . rand());
        $parameters['oauth_signature_method'] = $this->signature_method;
        $parameters['oauth_timestamp'] = time();
        $parameters['oauth_version'] = $this->version;
        
        if (isset($this->oauth_token)) {
            $parameters['oauth_token'] = $this->oauth_token;
        }
        
        // Sort alphabetically by key
        ksort($parameters);
        
        // Calculate the signature
        $signature = $this->create_signature($parameters, $url, $method);
        $parameters['oauth_signature'] = $signature;
        
        // And sort again, so the signature is correctly sorted
        ksort($parameters);
        
        // Create the OAuth-header
        $header = array();
        $header[] = $this->header_string($parameters);

        // Set curl-options
		//$options[CURLOPT_USERAGENT] = $this->getUserAgent();
		if (ini_get('open_basedir') == '' && ini_get('safe_mode' == 'Off')) {
            $options[CURLOPT_FOLLOWLOCATION] = true;
        }
		$options[CURLOPT_RETURNTRANSFER] = true;
		$options[CURLOPT_SSL_VERIFYPEER] = false;
		$options[CURLOPT_SSL_VERIFYHOST] = false;
		$options[CURLOPT_HTTPHEADER] = $header;
        if ($method == "POST") {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = $this->create_signature_encoded_string($parameters, "&");
        } else {
            $url .= "?" . $this->create_signature_encoded_string($parameters, "&");
        }

		$options[CURLOPT_URL] = $url;

		// Initiate curl
		$this->curl = curl_init();

		// Add the curl-options
		curl_setopt_array($this->curl, $options);

		// Execute
		$response = curl_exec($this->curl);
		$headers = curl_getinfo($this->curl);
        
		// Errors?
		$error_number = curl_errno($this->curl);
		$error_message = curl_error($this->curl);

        if ($error_number != 0) {
            // Errors :(
            throw new OAuthClientException($error_message, $error_number);
        }

        return $response;
    }
    
    /*
     * Create the Authentication-string needed in the header
     *
     * @return  string
     * @param   array   $parameters  The parameters needed in the Authentication-header
     */
    private function header_string(array $parameters) {
        $header = "OAuth " . $this->create_encoded_string($parameters, ", ");
        
        return $header;
    }

    /*
     * Create the OAuth signature, containing the secrets
     *
     * @return  string
     * @param   array   $parameters  The parameters needed in the request
     * @param   string  $url         The url where the request is going to
     * @param   string  $method      What kind of request is it?
     */
    private function create_signature($parameters = array(), $url = "", $method = "GET") {
        $parameterstring = $this->create_signature_encoded_string($parameters, "&");

        $base = $this->create_base_string($url, $method, $parameterstring);
        
        $signing_key = $this->create_signing_key();
        
        switch ($this->signature_method) {
            case "PLAINTEXT":
                $signature = $signing_key;
                break;
            default:
                $signature = base64_encode(hash_hmac('SHA1', $base, $signing_key, true));
                break;
        }

        return $signature;
    }
    
    /*
     * Create the signing key for the requests
     *
     * @return  string
     */
    private function create_signing_key() {
        $key = rawurlencode($this->consumer_secret) . "&" . rawurlencode($this->oauth_token_secret);
        return $key;
    }
    
    /*
     * Create the signature base string
     *
     * @return  string
     * @param   string  $url         The url to connect to
     * @param   string  $method      The request-method (POST or GET)
     * @param   array   $parameters  The parameters needed in the Authentication-header
     */
    private function create_base_string($url, $method = "GET", $parameters) {
        // Make sure the method is correct. Default is GET.
        $method = strtoupper($method);
        if ($method != "GET" && $method != "PUT" && $method != "DELETE") {
            $method = "GET";
        }
        
        $base = $method . "&" . rawurlencode($url) . "&" . rawurlencode($parameters);
        return $base;
    }
    
    /*
     * Create an encoded string needed for the signature
     *
     * @return  string
     * @param   array   $parameters  The parameters needed in the string
     * @param   string  $glue        How to glue the different parts together
     */
    private function create_signature_encoded_string($parameters, $glue = ", ") {
        $string = "";
        $attributes = array();
        
        ksort($parameters);
        
        foreach ($parameters as $key => $value) {
            $attributes[] = rawurlencode($key) . '=' . rawurlencode($value);
        }
        $string .= implode($glue, $attributes);
        
        return $string;
    }
    
    /*
     * Create an encoded string needed for requests (Authorization-header)
     *
     * @return  string
     * @param   array   $parameters  The parameters needed in the string
     * @param   string  $glue        How to glue the different parts together
     */
    private function create_encoded_string($parameters, $glue = ", ") {
        $string = "";
        $attributes = array();
        
        ksort($parameters);
        
        foreach ($parameters as $key => $value) {
            $attributes[] = rawurlencode($key) . '="' . rawurlencode($value) . '"';
        }
        $string .= implode($glue, $attributes);
        
        return $string;
    }
}

class OAuthClientException extends Exception {
    
    function __construct($message, $code = 0, Exception $previous = null) {
        echo "\n\nError  <br />\n=====\n\n" . $message . "  <br />\n\n";
    }
}