<div class="container" style="margin-top: 80px;">

 <div class='row'>
  <div class='col-md-6'>
  
   <h2>Sql Injection Detection Demostation</h2>
   <hr/> 

    <h2> Using Web From </h2>

	 <form method='post' action="<?=$this->baseUrl?>?action=login" id='login-form'>
	  <div class="form-group">
	    <label for="username">Username</label>
	    <input type="text" class="form-control" name='username' placeholder="Email">
	  </div>
	  <div class="form-group">
	    <label for="password">Password</label>
	    <input type="password" class="form-control" name='password' placeholder="Password">
	  </div>
 
	  <div class="checkbox">
	    <label>
	      <input type="checkbox"> Remember Password
	    </label>
	  </div>
	  <button type="submit" class="btn btn-primary">Submit</button>
	</form>
 
  </div>
 </div>

</div>