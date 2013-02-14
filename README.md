
php_http_auth
=============

Currently a stub library with only HTTP Digest support. Will support Basic Auth also in the future.


## Digest example

	$digest = new Php_Http_Auth\Digest(['username' => 'password']);

	if (!$digest->login()) {
		header('HTTP/1.1 401 Unauthorized');
		echo 'Failed to login.';
		exit;
	}


## License

Copyright 2012, [Markus Hedlund](http://markushedlund.com), [Snowfire](http://snowfire.net).  
Licensed under the MIT License.  
Redistributions of files must retain the above copyright notice.