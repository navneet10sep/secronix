<?php

require __DIR__ . "/vendor/autoload.php";

define("SECRONIXPATH","D:/xampp/htdocs/Research/website/secronix/");

include "lib/Attackbot.php";
include "lib/Attackauditor.php";
include "database/Attackpatterns.php";
include "database/vulunerabilityPatterns.php";
include "database/Detectorpatterns.php";

  
class Analyzer 
{

    public $pageOriginalContents;
    public $requestHeaders;
    public $errorMessagePatterns; 
    public $sourceCodePatterns; 
    public $detectorPatterns;
 

    function __construct($attackPatterns,$errorMessagePatterns,$sourceCodePatterns,$detectorPatterns){

        $this->pageOriginalContents = null;
        $this->requestHeaders = null;
        $this->attackPatterns = $attackPatterns;
        $this->errorMessagePatterns = $errorMessagePatterns; 
        $this->sourceCodePatterns = $sourceCodePatterns;
        $this->detectorPatterns = $detectorPatterns;
 
    } 

    //Start Page Output buffering 
    public function startOutputBuffering(){
      
      if( !$this-> ignoreAnalysisFlag() ) { 
        ob_start(); // Serverside Output Buffering Started 
      } 

    }


    /*Attack Bot pass addition header to execute the web page script without 
     interrupting so it can push some errors to the malicious requests made by attack bot
    */ 
    public function ignoreAnalysisFlag(){

       $requestHeaders = getallheaders(); 
       if( isset($requestHeaders['Secronix-analysis']) && ($requestHeaders['Secronix-analysis'] == true) ) { 
        return true;
       } else { 
        return false;
       }
    }

    public function cleanPageBuffer(){
            ob_end_clean();
    }

 
    /*
    Capture the page output buffer and save original page output before attacking at the web application  
    */
    public function getPageBuffer(){

      $output = ob_get_contents();
      if($this->pageOriginalContents == null){
         $this->pageOriginalContents = $output;
      }

    return $output;
    }


    public function start_dynamincAnalysis(){
   
        //Only run analysis attack bot sends malicious requests 
        if( !$this->ignoreAnalysisFlag() ) { 

            //Analysis of the output
            $output = $this->getPageBuffer();
            $this->cleanPageBuffer();
            
            $attackBot = new AttackBot($this->attackPatterns); 
            $attacksResponse = $attackBot->doAttack($output);

               if(is_array($attacksResponse)){


                /*Web Application responded to the malicious requests, Furthure process 
                AttackAuditor will inspect the response data of all the requests
                */
                $attackAuditor = new AttackAuditor(
                    $this->errorMessagePatterns,
                    $this->sourceCodePatterns, 
                    $this->detectorPatterns
                );

                $attackAuditor->doAudit($this->pageOriginalContents,$attacksResponse); 
       
                include "reporting/interface.php";
 
               } else {

                   if($attacksResponse == false){
                        
                        /* 
                        Loaded Web page didn't make any response to the any malicious response sent by the attackbot 
                        This may be due to the 404 or web applicaiton firewall resting the requests 
                        */
 
                        echo  $output;
                   }

               }
 

        }

    }


 
   

}


//Run the Analyzer Script 
$analysis = new Analyzer(
                $attackPatterns,
                $error_message_based_patterns,
                $source_code_based_patterns,
                $detectorPatterns
                );

$analysis->startOutputBuffering();

 
?>