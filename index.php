 
<?php 

//Plugin the Secure Code Analyzer
// This will Start buffering the output at this point 
include "secronix/analyzer.php";
 

define("APPPATH","D:/xampp/htdocs/Research/website/");
require_once('config/database.php');

//MVC Architecture - Page Controller 
include "controller/WebsiteController.php"; 
$website = new WebsiteController($conn);
$website->renderPage();



// Run the Analysis at last 
// This will perform the analysis captured output buffer
$analysis->start_dynamincAnalysis();


?>

 