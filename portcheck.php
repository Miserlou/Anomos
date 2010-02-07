<?php
$port = $_GET["port"];
$address = $_SERVER['REMOTE_ADDR'];
$checkport = fsockopen($address, $port, $errnum, $errstr, 2);

if(!$checkport){
       echo "open"
}else{
       echo "closed"
?>
