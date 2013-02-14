<?php

/**
* Based on code by 
*/

namespace Php_Http_Auth;

class Digest
{
	private $_auth;
	public $realm = 'Restricted area';
	
	/**
	* @param mixed $auth An array with user => password pairs
	* @return Digest
	*/
	public function __construct($auth)
	{
		$this->_auth = $auth;
	}
	
	// function to parse the http auth header
	private function _http_digest_parse($txt)
	{
	    // protect against missing data
	    $needed_parts = array('nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1);
	    $data = array();
	    $keys = implode('|', array_keys($needed_parts));

	    preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $txt, $matches, PREG_SET_ORDER);

	    foreach ($matches as $m) {
	        $data[$m[1]] = $m[3] ? $m[3] : $m[4];
	        unset($needed_parts[$m[1]]);
	    }

	    return $needed_parts ? false : $data;
	}

	public function login() {
	    if (empty($_SERVER["PHP_AUTH_DIGEST"])) {
	        header("HTTP/1.1 401 Unauthorized");
	        header("WWW-Authenticate: Digest realm=\"{$this->realm}\",qop=\"auth\",nonce=\"".uniqid()."\",opaque=\"".md5($this->realm)."\"");
	        return false;
	    }
	    if (!($data = $this->_http_digest_parse($_SERVER["PHP_AUTH_DIGEST"])) || !isset($this->_auth[$data["username"]]))
	        return false;
	    $A1 = md5($data["username"] . ":{$this->realm}:{$this->_auth[$data["username"]]}");
	    $A2 = md5($_SERVER["REQUEST_METHOD"].":{$data["uri"]}");
	    $valid_response = md5("{$A1}:{$data["nonce"]}:{$data["nc"]}:{$data["cnonce"]}:{$data["qop"]}:{$A2}");
	    if ($data["response"] != $valid_response)
	        return false;
	    return true;
	}
}
