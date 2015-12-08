<?php
	header('Content-Type: text/plain');
	foreach ($_POST as $key => $value) {
		echo "$key => $value\n";
	}
?>

Hier ist kein HTTP 303 Redirect.
