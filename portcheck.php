<?php
$port = $_GET["port"];
$address = $_SERVER['REMOTE_ADDR'];
$checkport = fsockopen($address, $port, $errnum, $errstr, 2); //The 2 is the time of ping in secs

if(!$checkport){
       echo "open"
}else{
       echo "closed"
?>
