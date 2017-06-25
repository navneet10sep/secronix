<?php

// Capture SQL statments 
// SELECT * FROM users WHERE username
// 





/*  Error Message Based Vulunerability Verification Patterns  */
$error_message_based_patterns = array(


	'XSS-INJECTION' => array(

	),


	'SQL_INEJCTION' => array(

		"/Unknown column/",
		"/secronix_column' in 'where clause' /", 
		"/Error description: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near/",
		"/The used SELECT statements have a different number of columns/", 
		"/A variable of a non-integer based type in LIMIT clause/",
		"/INSERT into autoincrement field which is not the first part in the composed primary key is unsafe/",
		"/Column '%s' in %s is ambiguous/",
		"/Unknown column '%s' in '%s'/",
		"/Duplicate key name '%s'/",
		"/Incorrect column specifier for column '%s'/",
		"/Incorrect parameter count to procedure '%s'/",
		"/Invalid use of group function/",
		"/Invalid use of NULL value/",
		"/Table '%s.%s' doesn't exist/",
		'/Unclosed quotation mark after the character string/',
		'/quoted string not properly terminated/',
		'/the used select statements have different number of columns/',
		'/Incorrect syntax near/',
		'/Syntax error in string in query expression/',
		'/Unclosed quotation mark before the character string/',
		'/Unexpected end of command in statement/',

	), 


 

);

/*  Source Code Based vulunerability verfiication Patterns */

$source_code_based_patterns = array( 


        //XSS Injection 
		'XSS-INJECTION' => array( 



		),


		//SQL Injection 
		'SQL-INJECTION' => array(



		),  


		// Senseetive Data reveal 
		'FILE-UPLOAD-ESC' =>  array(


		         "(?:\b(?:f(?:tp_(?:nb_)?f?(?:ge|pu)t|get(?:s?s|c)|scanf|write|open|read)|gz(?:(?:encod|writ)e|compress|open|read)|s(?:ession_start|candir)|read(?:(?:gz)?file|dir)|move_uploaded_file|(?:proc_|bz)open|call_user_func)|\$_(?:(?:pos|ge)t|session))\b", 



		), 

 
         //Remote command Execution 
		'REMOTE-COMMAND-EXEC' => array(


		), 




 );

 
?>