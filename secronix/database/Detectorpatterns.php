<?php

$detectorPatterns = array(

'SQL-INJECTION' => array(

         's1' => "/(INSERT INTO|UPDATE|SELECT|WITH|DELETE)+(.)+(VALUES|WHERE|SET)/i", 
         's2' => "/(INSERT INTO|UPDATE|SELECT|WITH|DELETE)+(.)+([TABLE_NAME])+(.)+(VALUES|WHERE|SET)/i",
         's3' =>  '@(?:[\w#_$]{1,128}|(?:(\[)|").{1,128}?(?(1)]|"))',

	),

'XSS-INJECTION' => array(

        "/(echo|print|sprintf)+(.)+(GET|REQUEST|POST)+(.)+(\;)/",
        "/(echo|print|sprintf)+(.)+(VARNAME)+(.)+(\;)/"

	)

);


?>