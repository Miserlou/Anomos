<!--Borrowed from Deluge, thanks. :)-->
<?php
error_reporting(0);
$host = $_SERVER['REMOTE_ADDR'];
$i = $_GET['port'];
$fp = fsockopen("$host",$i,$errno,$errstr,2);
if($fp){
    echo "open";
    fclose($fp);
}
else{
    echo "closed";
}
flush();
?> 
