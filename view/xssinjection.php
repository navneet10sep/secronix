<div class="container" style="margin-top: 80px;">

 <div class='row'>
  <div class='col-md-6'>
  
   <h2>Cross site scripting Detection Demostation</h2>
   <hr/> 

    <h2> Using Web From </h2>

	 <form method='post' action="<?=$this->baseUrl?>?action=register" id='login-form'>
	  <div class="form-group">
	    <label for="name">Name</label>
	    <input type="text" class="form-control" name='name' placeholder="name">
	  </div>
	  <div class="form-group">
	    <label for="email">Email Address </label>
	    <input type="text" class="form-control" name='email' placeholder="email address">
	  </div>
 
 
	  <button type="submit" class="btn btn-primary">Register</button>
	</form>
 
  </div>
 </div>

</div>