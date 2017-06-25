<?php

class AttackAuditor
{

   public $errorMessagePatterns; 
   public $sourceCodePatterns; 
   public $detectorPatterns; 
   public $sourceFiles; 
   public $vReports = array();


   function __construct($errorMessagePatterns,$sourceCodePatterns,$detectorPatterns){
 
     //Set the Vulunerability Verification Patterns 
     $this->errorMessagePatterns = $errorMessagePatterns; 
     $this->sourceCodePatterns = $sourceCodePatterns;
     $this->detectorPatterns = $detectorPatterns;
     $this->sourceFiles = $this->removeIgnoredFiles();
 
   }


public function removeIgnoredFiles(){

      //Parsed List 
      $pList = array();
      // Ignore files and folder 
      $ignoreList = array(
                    "D:/xampp/htdocs/Research/website/secronix/"
                    );

      foreach( get_included_files() as $sourceFile) {
          $sf = str_replace("\\","",$sourceFile);
          $sf = str_replace("/","",$sf);
          foreach($ignoreList as $ignored ){
                 $ignored = str_replace("/","",$ignored);
                 if(strpos($sf,$ignored) === false) {
                   $pList[]  = $sourceFile;
                 }
          }
      }

  return $pList;
}


  public function doAudit($pageOrigResponse,$attackBotInput){

  //Start Auditing
  //first match the page Original Resposne with the response after attack       
  
  //Calcualte the checksum of web page before making any malicious request 
  $origPageChecksum = md5($pageOrigResponse);

  
  //set Some flags 
  $vFound = false;

  /*
  Start Analysis
  First Phase: Match Original page checksum wih the checksum of page response to 
  malicious requests 
  */
 
  foreach($attackBotInput as $pageResponse) {




       if($origPageChecksum == md5($pageResponse['data']['response'])) {
       
         // No effect on the webpage to the malicious requests
         // Release the Page output 
         $vFound = false;
       
       } else { 

       	// Page response changed after the attack 
       	$vFound = false;

       	/*
       	  There can be two reasons for this change 
       	   1) Page have some dynamic contents that changes randomly or based on some criteria 
       	   2) Attack Bot malicious requested forced the web page server side script to throw 
       	      some errors and this leak some data in the form of fatal error or non fatal error 
       	      fatal error with http status code 200 will contains only message form the 
       	      error reporting service. In the case of non fatal errors page execution will not be 
       	      obscructed so data leakge will be found along wih the html data. there can be source code 
       	      snippets in the error repoting message. This we have the two type of patterns to verify 
       	      if there vulunerability exist 

       	      1) Error Message Based Vulunerability Verification Patterns 
       	      2) Source Code Based Vulunerability Verification Patterns 
       	*/

            //Check for SQL Injection Vulunerabilities
            if($pageResponse['attackInfo']['vType'] == 'SQL-INJECTION') { 
              $this->SQLInjectionAudit($pageResponse);
            }

             //Check for XSS Injection Vulunerabilities
            if($pageResponse['attackInfo']['vType'] == 'XSS-INJECTION') { 
              $this->XSSInjectionAudit($pageResponse);
            }

       }


   }


  }



public function SQLInjectionAudit($pageResponseData){

 /*
 // Parse the SQL query form the error message description 
 // Extract the Keywords 
 // Keyword 1 : Type of SQL query (SELECT,INSERT,UPDATE, DELETE, DROP and more )
 // Keyword 2: TableName 
 // Keyword 3: WHERE clause information - column name, Values passed to the columns 
 // Do reverse Engineering to constrct the parts of the query 

    // Create Dynamic Detector Pattern from the Data leakage Keywords 
    Example : SELECT [columnReference] FROM [tablename] WHERE [column1]
    Example:  SELECT + (.) + TABLENAME + (.) + WHERE + (.) + ? columnName 

    If 
    Pattern Matched  Marked it as Detected Vulunerabiltiy 
    Else
    // Vulunerability is still confirmed, Patter needs to be improved 

    Detectors Matching the Line will go furthure inspection to find the unfilterd variable concatination 
    Pattern Example : 
 */

    $pageResponse = $pageResponseData['data']['response'];

 
               $reg = '/SELECT (.+)/';
              
             
              preg_match($reg, $pageResponse, $match);
              if(!empty($match)){

 
                foreach($match as $m){
         
                     $dataLeakage = strip_tags($m);

                     //Remove Error message Noise form SQL query

                     $exDataLeak = explode("Error description:",$dataLeakage);
                     $parser = new PHPSQLParser\PHPSQLParser($exDataLeak[0], true);

                     $tableName = "";
                     $whereClause = $parser->parsed['WHERE'];
                     $columnName = "";

                     if(isset($parser->parsed['FROM']['0']['table'])){
                      $tableName = $parser->parsed['FROM']['0']['table'];
                     }


                     if(isset($whereClause['0']['base_expr'])){
                      $columnName = $whereClause['0']['base_expr'];
                     }
                   

                       // Degault SQL detector Pattern 
                       $detectorPattern = $this->detectorPatterns['SQL-INJECTION']['s1'];

                      if($tableName != "") {
                        $detectorPattern = $this->detectorPatterns['SQL-INJECTION']['s2'];
                        $detectorPatterns = str_replace("TABLE_NAME",$tableName,$detectorPattern);                    
                      }
                
/*                      if($columnName != "") {
                        $detectorPattern = $this->detectorPatterns['SQL-INJECTION']['s3'];
                        $detectorPatterns = str_replace("TABLE_NAME",$tableName,$detectorPattern);                    
                        $detectorPatterns = str_replace("COLUMN_NAME",$tableName,$detectorPattern);                    
                      }   
*/
                      /*
                      $createdSQL = new PHPSQLParser\PHPSQLCreator($parser->parsed);
                      if($createdSQL == $exDataLeak[0]) {
                        echo "SQL match";
                      }
                      */
                      $this->inspectSourceFiles($detectorPattern,$exDataLeak[0],$pageResponseData);

                }

             
              }  

}






public function inspectSourceFiles($detectorPattern,$sql,$pageResponseData){

      
      // Get all the Run-time included and required files
      // Files or folder that belongs to the framework or open source library can be added to the ignore list 
      // Thus it will decrase the code coverage

      foreach($this->sourceFiles as $sourceFile) {

        //Load Source code of the file 
        $sourceCode = file_get_contents($sourceFile);

        //Match Detector Pattern 
        $linesFound = preg_grep($detectorPattern, explode("\n", $sourceCode));


 

 
        foreach($linesFound as $key => $line) {

/*         echo "Vulunerability found at line number " . $key . " in source file ". $sourceFile;
           echo "<br/>";
           echo $line;
           echo "<br/>";*/
        
          $reportMessage = "";
          if($pageResponseData['attackInfo']['vType'] == 'SQL-INJECTION') {
            $reportMessage = "SQL injection vulunerability found in the file at line number ".$key." in file ".$sourceFile;
          }
          if($pageResponseData['attackInfo']['vType'] == 'XSS-INJECTION') {
            $reportMessage = "XSS injection vulunerability found in the file at line number ".$key." in file ".$sourceFile;
          }

          //Save Vulunerability Inforamtion 
          $this->vReports[] = array(

                        'attackInfo'        => $pageResponseData['attackInfo'],
                        'sourceFile'        => $sourceFile, 
                        'lineNumber'        => $key, 
                        'reportMessage'     => $reportMessage, 
                        'vType'             => $pageResponseData['attackInfo']['vType'],
                        'vSource'           => $line,
                        'vSql'              => $sql,
                        'form'              => $pageResponseData['form'],  
 
                      );

         }  
 
      }

} 


//Check for XSS Injection Vulunerabilities
public function XSSInjectionAudit($pageResponseData){

    $pageResponse = $pageResponseData['data']['response'];
 
               $reg = '/\<script\>alert\(\'secronix_xss\'\)\<\/script\>/';
              
             
              preg_match($reg, $pageResponse, $match);
              if(!empty($match)){

 
                foreach($match as $m){
    

               
                   $detectorPattern = "/(echo|print|sprintf)+(.)+(GET|REQUEST|POST)+(.)+(\;)/";
      
                     $this->inspectSourceFiles($detectorPattern,$m,$pageResponseData);
                }

             
              }  

 
}


}


?>