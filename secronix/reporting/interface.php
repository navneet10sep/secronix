<html>
<head>
	<title>Reporting interface for the Analyzer</title>
	<link rel="stylesheet" type="text/css" href="secronix/reporting/css/bootstrap.css">
	<link rel="stylesheet" type="text/css" href="secronix/reporting/css/nv-analyzer.css">
	<script src="secronix/reporting/js/jquery-3.1.1.js"></script>
  <script src="secronix/reporting/js/bootstrap.js"></script>

  <script type='text/javascript'>

   <?php

         $i = 0;
         foreach($attackAuditor->vReports as $report) {

   ?>

    function attackSimulation<?=$i?>(){
  
      <?php foreach($report['attackInfo']['payload'] as $input =>  $attackPattern) { ?>
         $("input[name=<?=$input?>]").val("<?=$attackPattern?>");
      <?php } ?>

        alert("Please submit the form");

    }

   <?php 
    $i = $i + 1;
    } 
   ?>

  </script>

</head>
<body>

<!-- Show page html ouput-->
<div class='nv-analyzer-page-container'>
<?=$output?>
</div>
<!-- Show page html ouput-->


     <div class='nv-analyzer-reporting-interface'>
          
 

                <div class="panel-group" id="accordion" role="tablist" aria-multiselectable="true">


      <?php
      
         $i = 0;
         foreach($attackAuditor->vReports as $report) {
      
      ?>     

                  <div class="panel panel-default">
                    <div class="panel-heading secronix-vhead" role="tab" id="sheading-<?=$i?>">
                      <h4 class="panel-title">
                        <a role="button" data-toggle="collapse" data-parent="#accordion" href="#scollapse-<?=$i?>" aria-expanded="true" aria-controls="scollapse-<?=$i?>">
                          <?=$report['reportMessage']?>  
                        </a>
                      </h4>
                    </div>
                    <div id="scollapse-<?=$i?>" class="panel-collapse collapse in" role="tabpanel" aria-labelledby="sheading-<?=$i?>">
                      <div class="panel-body">

                        <div class='row' style='word-break: break-word; '>

                            <div class='col-md-3'>

                            <strong>Type </strong> : <?=$report['vType']?> <br/>

                            <p>
                            SQL Injection is a code injection technique, used to attack data-driven applications, in which nefarious SQL statements are inserted into an entry field for execution 
                            </p>

                             <br/>
 

                            </div>

                            <div class='col-md-3'>
                             <strong>Vulunerable Source Code</strong> 

                             <div style='margin-top: 10px;'>
                             <code>
                             <?=$report['vSource']?>
                             </code>
                             </div>

                           
                             <div style='margin-top: 10px;'>
                              <strong>File</strong> <br/>
                              <a><?=$report['sourceFile']?></a>
                             </div>

                           
                             <div style='margin-top: 10px;'>
                              <strong>At Line Number</strong> <br/>
                              <a><?=$report['lineNumber']?></a>
                             </div>

                            </div>

                            <div class='col-md-3'>

                               <strong> Attack Payload </strong> 
                               <div style='margin-top: 10px;'>
                               
                              Form id : #<?=$report['form']['id']?> <br/>

                              <?php
                              foreach($report['attackInfo']['payload'] as $input =>  $attackPattern) {
                              ?>
                              <?=$input?> : <?=$attackPattern?> <br/>
                              <?php  } ?>

                               </div>
                                    
                               <div style='margin-top: 10px;'>
                               <strong>  SQL Query After SQL Injection </strong> <br/>
                               <code>
                               <?=$report['vSql']?>
                               </code>
                               </div>
                               <br/>
                               <button class='btn btn-default' onclick="attackSimulation<?=$i?>()">Run Attack Simulation</button>

                            </div>

                            <div class='col-md-3'>

                               <strong> Actionable Guidence and Infroamtion </strong> 
                               <div style='margin-top: 10px;'>


                               it's looks like your vulunerable source do concats the 
                               variable that is not filtered for the unwanted characters. 
                               Please use the following function to sanatize  

                               <code>mysqli_real_escape_string()</code> <br/>
                               <code>html_entities_encode()</code>
                               <br/>
                               <br/>
                               <strong>  Example of Code Snippet </strong> 
                               <div style='margin-top: 10px;'>
                               <code>
                                 $sql = "SELECT * FROM users WHERE username = '". mysqli_real_escape_string($username) ."' AND password = '". mysqli_real_escape_string($password) ."' ";
                               </code>
                               </div>
   

                               </div>

                            </div>

                        </div>

                      </div>
                    </div>
                  </div>

                         
                     
                                      <?php 
                                        $i = $i + 1;
                                        } 
                                      ?>

                 </div>
 

  
     		</div>
     	 

 
</body>
</html>