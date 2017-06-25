<?php


$attackPatterns  = array(

	'SQL-INJECTION' => array(

	//Force Error by injecting INVALID column 'secornix_column' in the SQL query 
    // This will work for SELECT queries contactiinging vars in the WHERE clause  
	// Example : SELECT * FORM tableName WHERE validcolumn = '' OR seconix_column = '123
	"' OR 1 = 1 AND secronix_column = '123",
 
	// Force error by injection the attack in the ORDER BY clause  
  	// Force error in the INSERT query 
  	// Force erorr int he UPDATE query 
  	// Force Error in the DELETE query 

	), 

	'XSS-INJECTION' => array(


       "<script>alert('secronix_xss')</script>",
   

	)


);



?>