<?php

class WebsiteController
{

	public  $baseUrl = "http://localhost/research/website/";
	public $conn; 


	function __construct($conn){

        //Database Connection Object
		$this->conn = $conn;
	}


	public function login(){
    
     $username = $_REQUEST['username'];
     $password = $_REQUEST['password'];

      if(!empty($username) && !empty($password) ) {
      
       // Putting SQL Injection Vulunerability in the Code
       $sql = "SELECT * FROM users WHERE username = '". $username ."' AND password = '". $password ."' ";

 
			$result = $this->conn->query($sql);

           if($result) {



				if ($result->num_rows > 0) {
				    // output data of each row
				    while($row = $result->fetch_assoc()) {
				        

	                    include APPPATH."view/login.php";
				      
				    }
			   	} else {
				    echo "0 results";
			 	}

          } else { 
           
                echo(mysqli_error($this->conn));
                echo $sql; 
          }


      } 

	}


	public function register(){
    
     $name = $_REQUEST['name'];
     $email = $_REQUEST['email'];

      if(!empty($name) && !empty($email) ) {
       
           echo "Welcome ". $_REQUEST['name']; 

      } 

	}




	public function renderPage() {

	    //Include Header View 
	    include APPPATH."view/header.php"; 
	    //Include Sidebar View 
	    include APPPATH."view/sidebar.php";

          
          //Render the Index Page
		  if(!isset($_REQUEST['page']) && !isset($_REQUEST['action'])) {
		   include APPPATH."view/content.php"; 
		  } else { 

            //Access only to the API's 
		  	if(isset($_REQUEST['action'])) {

			          if($_REQUEST['action'] == 'view') {

					   if($_REQUEST['page'] == 'sqlinjection') {
					    include APPPATH."view/sqlinjection.php"; 
					   }

					   if($_REQUEST['page'] == 'xssinjection') {
					    include APPPATH."view/xssinjection.php"; 
					   }


					  } else { 
			             if($_REQUEST['action'] == 'login') { $this->login(); }
			             if($_REQUEST['action'] == 'register') { $this->register(); }
					  }
		    }
		  }

	    include APPPATH."view/footer.php";
	}







}


?>