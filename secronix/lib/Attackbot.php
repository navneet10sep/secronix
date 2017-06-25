<?php

//Library to the Parse them HTML DOM in PHP 
include SECRONIXPATH."vendors/simple_html_dom.php";
 
class AttackBot 
{

    function __construct($attackPatterns){
      $this->attackPatterns = $attackPatterns;
    }
 
	public function doAttack($output){
     
        //Target Web Page Loaded 
        //In next Phase, Detect all the Web Froms 
    	$formsData = $this->detectWebForm($output);

        if(count($formsData) == 0 ) {  
             echo false;
        } else { 
  
            $attacksResponse = $this->sendMaliciousRequests($formsData);
            if( count($attacksResponse) == 0 ) {
              return false;
            } else { 
              return $attacksResponse;
            }
        }
 
    return false;
    }


    public function sendMaliciousRequests($formsData){
    
     $responseDataStorage = array();

     //loop through all the detected forms
     foreach($formsData as $form) {
     
      $attackPayloads = $this->prepareAttackPayload($form);
      
         //loop through all the created attack payloads with various vulunerabilities types 
         foreach($attackPayloads as $vType => $payloads) {

            //each vulunerability type has many attack patterns based on the different method of exploitation 
            foreach($payloads as $payload) {

            //Send Request 


print_r($payload);

            $responseData = $this->callPage($form['action'],strtoupper($form['method']),$payload,true);
            $responseDataStorage[] = array(  

                                    'attackInfo' => array(
                                                    'vType'   => $vType, 
                                                    'payload' => $payload
                                     ), 
                                    
                                    'data'       => $responseData,
                                    'form'       => $form 
                                    
                                    );



            }
print_r($responseData);
            die();

         }

     }

    return $responseDataStorage;
    }


    public function prepareAttackPayload($form){


       // Prepare the attack payload
       // Pick Malicious Date
       $attackPayloads = array(); 

       $i = 0;  
       foreach($this->attackPatterns as $attackType => $patterns ) {

       foreach($patterns as $pattern) {
       foreach($form['inputs'] as $input) {
            $attackPayloads[$attackType][$i][ $input['name'] ] = $pattern;
       }}

       $i = $i + 1;
       }


    return $attackPayloads;
    }

    public function getAttackPattern($vulnType){

          


         if($vulnType == 'SQLINJECTION') {
            return "' 1 = 1 AND secronix_column = '123 ";
         }


         

    }

 

    public function detectWebForm($dom){

     //Parase the HTML Dom using PHP simple_html_dom library 
     $html = str_get_html($dom); 

     //Detect for the <form> tag 
     $webFroms = $html->find('form');
     $formsData = array();

     //loop through all the webforms the reterieve their input parameters
     foreach($webFroms as $form) {
       
         $formsData[] = array( 

                              'action' => $form->action, 
                              'method' => $form->method,
                              'id'     => $form->id,
                              'inputs' => $this->detectInputParameters($form)  
                          );
     } 


    //Return all the Web Forms 
    return $formsData;
    }


    public function detectInputParameters($formDom) {

        $inputData = array(); 
        $inputs = $formDom->find("input");

        foreach($inputs as $input){

          $inputData[] = array(
                         'type' => $input->type,
                         'name' => $input->name
                       );

        }
       
     //Return Forms Input Parameters 
     return $inputData;
    }

 

	public function callPage($url,$method,$requestData,$analysisHeader){

 
	  	$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL,$url);

		 if($method == 'POST') {
		 curl_setopt($ch, CURLOPT_POST, 1);
		 curl_setopt($ch, CURLOPT_POSTFIELDS, 
		 http_build_query($requestData));
         }
 

        /*
        Set additional header in the request data 
        to tell analyzer not to run the analysis for request made by the attack bot 
        so it don't create a infinite loop 
        */
        if($analysisHeader == true) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Secronix-analysis : '. true
            ));
        }



		// receive server response ...
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_HEADER, 1);
		$server_output = curl_exec ($ch);
        //check http status code 
        $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);



		curl_setopt($ch, CURLOPT_HEADER, 0);
		$server_output = curl_exec ($ch);


		curl_close ($ch);

        // Some web servers may send the compressed Gzip encoded HTML Data 
        // Detect and Decode the Gzip encoded data
        // Detection based on the RFC 1952 Gzip Header 
        // http://www.gzip.org/zlib/rfc-gzip.html#member-format

		/*
		Example of Gzip Header
		+---+---+---+---+---+---+---+---+---+---+
		|ID1|ID2|CM |FLG|     MTIME     |XFL|OS | (more--&gt;)
		+---+---+---+---+---+---+---+---+---+---+

		The value of ID1 is "\x1f"
		The value of ID2 is "\x8b"
		The value of CM is "\x08" (or just 8...)

		Alternatively this can be detected based on the 
		Accept-Encoding: gzip header value, but headers can be malformed or doesn't have the Accept-Encoding index in the header data  
		*/

        $is_gzip = 0 === mb_strpos($server_output , "\x1f" . "\x8b" . "\x08"); 
        if($is_gzip) {
		$server_output = gzinflate(substr($server_output, 10));
        }

  
		 
    return array( 'response' => $server_output , 'status_code' =>  $status_code  );
	}


}

 

?>